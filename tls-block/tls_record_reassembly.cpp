#include "tls_record_reassembly.h"
#include "packet_parser.h"
#include "rst_sender.h"

#include <algorithm>
#include <chrono>
#include <utility>


// ============================================================
// Internal time helper
// ============================================================

static uint64_t current_time_sec()
{
    using namespace std::chrono;

    return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}


// ============================================================
// Internal TLS Record helpers
// ============================================================

static bool is_valid_tls_record_type(uint8_t content_type)
{
    if(content_type == 0x14) return true; // ChangeCipherSpec
    if(content_type == 0x15) return true; // Alert
    if(content_type == 0x16) return true; // Handshake
    if(content_type == 0x17) return true; // Application Data

    return false;
}


static bool is_valid_tls_record_version(uint8_t major, uint8_t minor)
{
    if(major != 0x03) return false;
    if(minor > 0x04) return false;

    return true;
}


// ============================================================
// TCP sequence comparison
// ============================================================

bool tcp_seq_before(uint32_t a, uint32_t b)
{
    return static_cast<int32_t>(a - b) < 0;
}


bool tcp_seq_after(uint32_t a, uint32_t b)
{
    return static_cast<int32_t>(a - b) > 0;
}


// ============================================================
// TCP reassembly
// ============================================================

ReassemblyResult feed_tcp_reassembly(const Flow_Key& key, Flow_Entry& flow, uint32_t seq, const uint8_t* payload, size_t payload_len)
{
    if(payload_len == 0) return ReassemblyResult::OK;
    if(payload == nullptr) return ReassemblyResult::BROKEN_FLOW;

    flow.has_seen_c2s_payload = true;

    if(seq == flow.c2s_expected_seq)
    {
        ReassemblyResult append_result = append_to_tls_record_buffer(key, flow, payload, payload_len);
        if(append_result != ReassemblyResult::OK) return append_result;

        flow.c2s_expected_seq += payload_len;

        ReassemblyResult drain_result = drain_contiguous_out_of_order_segments(key, flow);
        if(drain_result != ReassemblyResult::OK) return drain_result;

        ReassemblyResult parse_result = try_parse_tls_records(key, flow);
        if(parse_result != ReassemblyResult::OK) return parse_result;

        return ReassemblyResult::OK;
    }

    if(tcp_seq_after(seq, flow.c2s_expected_seq))
    {
        return store_out_of_order_segment(key, flow, seq, payload, payload_len);
    }

    return ReassemblyResult::OK; // 여기까지 온다면 retransmission이므로 무시
}


ReassemblyResult store_out_of_order_segment(const Flow_Key& key, Flow_Entry& flow, uint32_t seq, const uint8_t* payload, size_t payload_len)
{
    (void)key;

    if(payload_len == 0) return ReassemblyResult::OK;
    if(payload == nullptr) return ReassemblyResult::BROKEN_FLOW;

    if(flow.out_of_order_buffer.find(seq) != flow.out_of_order_buffer.end())
    {
        DEBUG_LOG("duplicate out-of-order segment ignored");
        return ReassemblyResult::OK;
    } // out-of-order retransmission이므로 무시

    if(flow.out_of_order_buffer.size() >= MAX_OOO_SEGMENTS)
    {
        ERROR_LOG("out-of-order segment count exceeded");
        return ReassemblyResult::BROKEN_FLOW;
    } // flow 하나가 너무 많은 out-of-order segment를 쌓으면 공격 상황일 수 있기에 비정상처리

    if(payload_len > MAX_OOO_BYTES - flow.out_of_order_bytes)
    {
        ERROR_LOG("out-of-order byte limit exceeded");
        return ReassemblyResult::BROKEN_FLOW;
    } // out-of-order buffer에 저장된 전체 payload byte 수가 너무 많으면 공격 상황일 수 있기에 비정상처리

    OutOfOrderSegment segment;

    segment.seq = seq;
    segment.payload.assign(payload, payload + payload_len);

    flow.out_of_order_buffer.emplace(seq, std::move(segment));
    flow.out_of_order_bytes += payload_len;

    DEBUG_LOG("out-of-order segment stored");

    return ReassemblyResult::OK;
} // 공격자가 gap을 남긴 상태로 out-of-order segment만 계속 보내서 timeout을 회피하는 걸 막기 위해 last_progress_time을 갱신하지 않음


ReassemblyResult drain_contiguous_out_of_order_segments(const Flow_Key& key, Flow_Entry& flow)
{
    while(true)
    {
        auto it = flow.out_of_order_buffer.find(flow.c2s_expected_seq);
        if(it == flow.out_of_order_buffer.end()) break;

        OutOfOrderSegment segment = std::move(it->second);
        flow.out_of_order_buffer.erase(it);

        if(segment.payload.size() > flow.out_of_order_bytes)
            flow.out_of_order_bytes = 0;
        else
            flow.out_of_order_bytes -= segment.payload.size();
        // 정상적으로는 segment.payload.size()가 out_of_order_bytes보다 클 수 없다. 방어적으로 underflow를 막기 위함

        ReassemblyResult append_result = append_to_tls_record_buffer(key, flow, segment.payload.data(), segment.payload.size());
        if(append_result != ReassemblyResult::OK) return append_result;

        flow.c2s_expected_seq += segment.payload.size();
    }

    return ReassemblyResult::OK;
}


ReassemblyResult append_to_tls_record_buffer(const Flow_Key& key, Flow_Entry& flow, const uint8_t* data, size_t data_len)
{
    (void)key;

    if(data_len == 0) return ReassemblyResult::OK;
    if(data == nullptr) return ReassemblyResult::BROKEN_FLOW;

    if(data_len > MAX_TLS_RECORD_BUFFER_SIZE - flow.tls_record_buffer.size())
    {
        ERROR_LOG("TLS record buffer size exceeded");
        return ReassemblyResult::BROKEN_FLOW;
    } // TLS record buffer가 너무 커지면 공격 상황일 수 있기에 비정상처리

    flow.tls_record_buffer.insert(flow.tls_record_buffer.end(), data, data + data_len);
    flow.last_progress_time = current_time_sec();

    return ReassemblyResult::OK;
}


// ============================================================
// TLS Record reassembly
// ============================================================

ReassemblyResult try_parse_tls_records(const Flow_Key& key, Flow_Entry& flow)
{
    while(flow.tls_record_buffer.size() >= 5)
    {
        uint8_t content_type = flow.tls_record_buffer[0];
        uint8_t version_major = flow.tls_record_buffer[1];
        uint8_t version_minor = flow.tls_record_buffer[2];

        if(!is_valid_tls_record_type(content_type))
        {
            DEBUG_LOG("not a TLS record: invalid content type");
            return ReassemblyResult::NOT_TARGET;
        } // SYN 이후 첫 Client->Server payload stream이 TLS Record가 아니라면 HTTPS/TLS ClientHello 추적 대상이 아님

        if(!is_valid_tls_record_version(version_major, version_minor))
        {
            DEBUG_LOG("not a TLS record: invalid version");
            return ReassemblyResult::NOT_TARGET;
        } // TLS Record version 계열이 아니면 HTTPS/TLS ClientHello 추적 대상이 아님

        uint16_t tls_record_body_length = 0;

        tls_record_body_length |= static_cast<uint16_t>(flow.tls_record_buffer[3]) << 8;
        tls_record_body_length |= static_cast<uint16_t>(flow.tls_record_buffer[4]);

        if(tls_record_body_length > MAX_TLS_RECORD_BODY_LENGTH)
        {
            ERROR_LOG("TLS record body length exceeded");
            return ReassemblyResult::BROKEN_FLOW;
        } // 공격자가 Length를 크게 설정해서 buffer를 오래 잡거나 리소스를 고갈시킬 수 있기 때문에 TLS Record body length가 너무 크면 비정상처리

        size_t tls_record_total_length = 5 + static_cast<size_t>(tls_record_body_length);

        if(flow.tls_record_buffer.size() < tls_record_total_length)
            return ReassemblyResult::OK; // Body 전체가 아직 모이지 않은 상황 (정상적인 fragmentation)

        TLS_Record record;

        std::copy(flow.tls_record_buffer.begin(),
                  flow.tls_record_buffer.begin() + 5,
                  record.header.begin());

        record.body.assign(flow.tls_record_buffer.begin() + 5,
                           flow.tls_record_buffer.begin() + tls_record_total_length);

        ReassemblyResult push_result = push_tls_record_queue(key, flow, record);
        if(push_result != ReassemblyResult::OK) return push_result;

        flow.tls_record_buffer.erase(flow.tls_record_buffer.begin(), flow.tls_record_buffer.begin() + tls_record_total_length);
        // 완성된 TLS Record는 buffer에서 제거

    } // TCP byte stream 안에 TLS Record가 여러 개 연속해서 들어올 수 있기 때문에 buffer에 데이터가 남아있으면 반복

    return ReassemblyResult::OK;
}


ReassemblyResult push_tls_record_queue(const Flow_Key& key, Flow_Entry& flow, const TLS_Record& record)
{
    if(flow.tls_record_queue.size() >= MAX_TLS_RECORD_QUEUE_SIZE)
    {
        ERROR_LOG("TLS record queue size exceeded");
        return ReassemblyResult::BROKEN_FLOW;
    } // 하나의 flow에서 2단계가 처리하지 못하는 TLS Record가 너무 많이 쌓이면 공격 상황일 수 있기에 비정상처리

    flow.tls_record_queue.push(record);
    flow.last_progress_time = current_time_sec();

    notify_ready_flow(key);

    return ReassemblyResult::OK;
}


void notify_ready_flow(const Flow_Key& key)
{
    ready_flow_queue.push(key);
    ready_flow_cv.notify_one();
}


// ============================================================
// packet handling
// ============================================================

void handle_captured_packet(const uint8_t* packet, size_t packet_len)
{
    const hb_eth_hdr* eth_hdr = nullptr;
    const hb_ip_hdr* ip_hdr = nullptr;
    const hb_tcp_hdr* tcp_hdr = nullptr;
    const uint8_t* tcp_payload = nullptr;
    size_t tcp_payload_len = 0;

    if(!parse_packet_headers(packet, packet_len, &eth_hdr, &ip_hdr, &tcp_hdr, &tcp_payload, &tcp_payload_len))
        return; // Ethernet/IPv4/TCP packet이 아니거나, 길이가 이상하거나, IP fragment면 바로 return

    (void)eth_hdr; // RST를 raw socket으로 보내기로 했기 때문에 Ethernet MAC이 필요 없음. eth_hdr는 파싱은 하지만 사용하지 않는다

    bool should_reset = false;
    Flow_Key reset_key;

    { // mutex lock용 괄호
        std::lock_guard<std::mutex> lock(flow_table_mutex);

        Flow_Key key;
        Flow_Entry* flow = find_flow_bidirectional(ip_hdr, tcp_hdr, &key);

        uint8_t flags = tcp_hdr->flags_value();

        if(flow == nullptr) // 캡쳐한 패킷에 대응하는 flow가 없다면 새로운 flow생성
        {
            if((flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0)
                flow = create_flow_from_syn(ip_hdr, tcp_hdr, &key);

            else return;

            if(flow == nullptr) return;
        }

        flow->last_seen_time = current_time_sec();

        if(is_server_to_client(*flow, ip_hdr, tcp_hdr))
        {
            if((flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) != 0)
            {
                flow->server_syn_seq = tcp_hdr->seq_num_value();
                flow->s2c_next_seq = flow->server_syn_seq + 1;
                flow->have_s2c_next_seq = true;
            }

            if((flags & TCP_FLAG_ACK) != 0)
            {
                flow->last_s2c_ack = tcp_hdr->ack_num_value();
                flow->have_last_s2c_ack = true;
            }

            return;
        }

        if(!is_client_to_server(*flow, ip_hdr, tcp_hdr)) return;

        if((flags & TCP_FLAG_ACK) != 0)
        {
            flow->last_c2s_ack = tcp_hdr->ack_num_value();
            flow->have_last_c2s_ack = true;

            flow->s2c_next_seq = flow->last_c2s_ack;
            flow->have_s2c_next_seq = true;
        }

        if(tcp_payload_len == 0) return;

        uint32_t seq = tcp_hdr->seq_num_value();

        ReassemblyResult result = feed_tcp_reassembly(key, *flow, seq, tcp_payload, tcp_payload_len);

        if(result == ReassemblyResult::NOT_TARGET)
        {
            remove_flow_without_rst(key);
            return;
        }

        if(result == ReassemblyResult::BROKEN_FLOW)
        {
            should_reset = true;
            reset_key = key;
        }
    } // mutex unlock용 괄호

    if(should_reset)
        terminate_flow_with_rst(reset_key, ResetReason::BROKEN_FLOW);

    cleanup_expired_flows();
}