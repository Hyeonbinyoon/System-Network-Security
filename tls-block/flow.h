#pragma once

#include "common.h"
#include "hb_headers.h"

#include <array>
#include <condition_variable>
#include <stddef.h>
#include <stdint.h>
#include <map>
#include <mutex>
#include <queue>
#include <vector>


// ============================================================
// Flow key
// ============================================================

struct Flow_Key
{
    uint32_t client_ip = 0;
    uint16_t client_port = 0;
    uint32_t server_ip = 0;
    uint16_t server_port = 0;

    bool operator<(const Flow_Key& other) const
    {
        if(client_ip != other.client_ip) return client_ip < other.client_ip;
        if(client_port != other.client_port) return client_port < other.client_port;
        if(server_ip != other.server_ip) return server_ip < other.server_ip;

        return server_port < other.server_port;
    }
};


// ============================================================
// Out-of-order TCP segment
// ============================================================

struct OutOfOrderSegment
{
    uint32_t seq = 0;
    std::vector<uint8_t> payload;
};


// ============================================================
// Completed TLS Record
// ============================================================

struct TLS_Record
{
    std::array<uint8_t, 5> header = {};
    std::vector<uint8_t> body;
};


// ============================================================
// TLS Handshake assemble state
// ============================================================

enum class HandshakeAssembleState
{
    WAIT_HANDSHAKE_HEADER,
    WAIT_HANDSHAKE_BODY
};


// ============================================================
// Flow entry
// ============================================================

struct Flow_Entry
{
    uint32_t client_ip = 0;
    uint16_t client_port = 0;
    uint32_t server_ip = 0;
    uint16_t server_port = 0;

    bool has_seen_c2s_payload = false;

    uint32_t client_syn_raw_seq = 0;
    uint32_t c2s_expected_seq = 0;

    uint32_t server_syn_seq = 0;
    uint32_t s2c_next_seq = 0;
    bool have_s2c_next_seq = false;

    uint32_t last_c2s_ack = 0;
    bool have_last_c2s_ack = false;

    uint32_t last_s2c_ack = 0;
    bool have_last_s2c_ack = false;

    std::map<uint32_t, OutOfOrderSegment> out_of_order_buffer;
    size_t out_of_order_bytes = 0;

    std::vector<uint8_t> tls_record_buffer;
    std::vector<uint8_t> tls_handshake_buffer;
    std::queue<TLS_Record> tls_record_queue;

    uint64_t last_seen_time = 0;
    uint64_t last_progress_time = 0;

    HandshakeAssembleState handshake_assemble_state = HandshakeAssembleState::WAIT_HANDSHAKE_HEADER;
    uint8_t current_handshake_type = 0;
    uint32_t expected_handshake_body_len = 0;
    uint32_t accumulated_handshake_body_len = 0;
};


// ============================================================
// Global flow table / ready queue
// Defined in flow.cpp
// ============================================================

extern std::map<Flow_Key, Flow_Entry> flow_table;
extern std::queue<Flow_Key> ready_flow_queue;

extern std::mutex flow_table_mutex;
extern std::condition_variable ready_flow_cv;


// ============================================================
// Flow management functions
// ============================================================

Flow_Key make_flow_key(uint32_t client_ip, uint16_t client_port, uint32_t server_ip, uint16_t server_port);
Flow_Entry* find_flow_bidirectional(const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr, Flow_Key* found_key);
Flow_Entry* create_flow_from_syn(const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr, Flow_Key* created_key);

void remove_flow_without_rst(const Flow_Key& key);
void cleanup_expired_flows();

bool is_idle_timeout_flow(const Flow_Entry& flow, uint64_t now);
bool is_progress_timeout_flow(const Flow_Entry& flow, uint64_t now);