/*
 * find_flow_bidirectional()
 * create_flow_from_syn()
 * remove_flow_without_rst()
 * → 호출자가 flow_table_mutex를 잡은 상태에서 호출한다고 가정

 * cleanup_expired_flows()
 * → 내부에서 flow_table_mutex를 잡음
 */


#include "flow.h"
#include "rst_sender.h"

#include <chrono>
#include <utility>
#include <vector>

// ============================================================
// Global flow table / ready queue
// ============================================================

std::map<Flow_Key, Flow_Entry> flow_table;
std::queue<Flow_Key> ready_flow_queue;

std::mutex flow_table_mutex;
std::condition_variable ready_flow_cv;


// ============================================================
// Internal time helper
// ============================================================

static uint64_t current_time_sec()
{
    using namespace std::chrono;

    return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}


// ============================================================
// Flow key
// ============================================================

Flow_Key make_flow_key(uint32_t client_ip, uint16_t client_port, uint32_t server_ip, uint16_t server_port)
{
    Flow_Key key;

    key.client_ip = client_ip;
    key.client_port = client_port;
    key.server_ip = server_ip;
    key.server_port = server_port;

    return key;
}


// ============================================================
// Flow lookup
// 들어온 패킷이 client->server방향이던, server->client방향이던, 매핑되는 client->server Flow_Entry를 찾아 반환하고 입력받은 key를 설정하는 함수
// ============================================================

Flow_Entry* find_flow_bidirectional(const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr, Flow_Key* found_key)
{
    if(ip_hdr == nullptr || tcp_hdr == nullptr) return nullptr;

    uint32_t src_ip = ip_hdr->src_ip_value();
    uint32_t dst_ip = ip_hdr->dst_ip_value();

    uint16_t src_port = tcp_hdr->src_port_value();
    uint16_t dst_port = tcp_hdr->dst_port_value();

    Flow_Key forward_key = make_flow_key(src_ip, src_port, dst_ip, dst_port);
    auto forward_it = flow_table.find(forward_key);

    if(forward_it != flow_table.end())
    {
        if(found_key != nullptr)
        {
            *found_key = forward_key;
        }

        return &forward_it->second;
    }

    Flow_Key reverse_key = make_flow_key(dst_ip, dst_port, src_ip, src_port);
    auto reverse_it = flow_table.find(reverse_key);

    if(reverse_it != flow_table.end())
    {
        if(found_key != nullptr)
        {
            *found_key = reverse_key;
        }

        return &reverse_it->second;
    }

    return nullptr;
}


// ============================================================
// Flow creation
// 이미 입력한 key가 table에 존재한다면 기존 flow를 반환하고, 없다면 Flow_Entry를 만들어 입력한 key와 함께 table에 삽입
// ============================================================

Flow_Entry* create_flow_from_syn(const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr, Flow_Key* created_key)
{
    if(ip_hdr == nullptr || tcp_hdr == nullptr) return nullptr;

    uint32_t client_ip = ip_hdr->src_ip_value();
    uint32_t server_ip = ip_hdr->dst_ip_value();

    uint16_t client_port = tcp_hdr->src_port_value();
    uint16_t server_port = tcp_hdr->dst_port_value();

    Flow_Key key = make_flow_key(client_ip, client_port, server_ip, server_port);

    auto existing_it = flow_table.find(key);
    if(existing_it != flow_table.end())
    {
        if(created_key != nullptr)
            *created_key = key;

        return &existing_it->second;
    }

    uint64_t now = current_time_sec();

    Flow_Entry flow;

    flow.client_ip = client_ip;
    flow.client_port = client_port;
    flow.server_ip = server_ip;
    flow.server_port = server_port;

    flow.has_seen_c2s_payload = false;

    flow.client_syn_raw_seq = tcp_hdr->seq_num_value();
    flow.c2s_expected_seq = flow.client_syn_raw_seq + 1;

    flow.last_seen_time = now;
    flow.last_progress_time = now;

    auto insert_result = flow_table.emplace(key, std::move(flow));

    if(created_key != nullptr)
        *created_key = key;

    INFO_LOG("flow created from SYN");

    return &insert_result.first->second;
}



// ============================================================
// Flow remove
// ============================================================

void remove_flow_without_rst(const Flow_Key& key)
{
    auto it = flow_table.find(key);

    if(it == flow_table.end()) return;

    flow_table.erase(it);

    DEBUG_LOG("flow removed without RST");
}


// ============================================================
// Timeout checks
// ============================================================

bool is_idle_timeout_flow(const Flow_Entry& flow, uint64_t now)
{
    if(flow.has_seen_c2s_payload) return false;
    if(!flow.out_of_order_buffer.empty()) return false;
    if(!flow.tls_record_buffer.empty()) return false;
    if(!flow.tls_handshake_buffer.empty()) return false;
    if(!flow.tls_record_queue.empty()) return false;

    return now > flow.last_seen_time && (now - flow.last_seen_time) > FLOW_IDLE_TIMEOUT;
}


bool is_progress_timeout_flow(const Flow_Entry& flow, uint64_t now)
{
    bool has_reassembly_state = false;

    if(flow.has_seen_c2s_payload) 
        has_reassembly_state = true;

    if(!flow.out_of_order_buffer.empty()) 
        has_reassembly_state = true;

    if(!flow.tls_record_buffer.empty())
        has_reassembly_state = true;

    if(!flow.tls_handshake_buffer.empty())
        has_reassembly_state = true;

    if(!flow.tls_record_queue.empty())
        has_reassembly_state = true;

    if(!has_reassembly_state) return false;

    return now > flow.last_progress_time && (now - flow.last_progress_time) > FLOW_PROGRESS_TIMEOUT;
}


// ============================================================
// Cleanup expired flows
// ============================================================

void cleanup_expired_flows()
{
    std::vector<Flow_Key> idle_remove_keys;
    std::vector<Flow_Key> broken_reset_keys;

    uint64_t now = current_time_sec();

    { // mutex lock용 괄호
        std::lock_guard<std::mutex> lock(flow_table_mutex);

        for(const auto& entry : flow_table)
        {
            const Flow_Key& key = entry.first;
            const Flow_Entry& flow = entry.second;

            if(is_idle_timeout_flow(flow, now))
                idle_remove_keys.push_back(key);
            else if(is_progress_timeout_flow(flow, now))
                broken_reset_keys.push_back(key);
        }

        for(const Flow_Key& key : idle_remove_keys)
        {
            remove_flow_without_rst(key);
        }
    } // mutex unlock용 괄호

    for(const Flow_Key& key : broken_reset_keys)
    {
        terminate_flow_with_rst(key, ResetReason::BROKEN_FLOW);
    }
    // terminate_flow_with_rst()는 내부에서 다시 flow_table을 찾아서 RST를 보내고 flow를 삭제하기 떄문에 flow_table_mutex를 잡음

} // 여러 thread가 동시에 flow를 갱신할 수 있으므로, terminate_flow_with_rst() 내부에서는 다시 lookup해야 한다.