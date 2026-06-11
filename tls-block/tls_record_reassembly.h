#pragma once

#include "flow.h"

#include <stddef.h>
#include <stdint.h>


// ============================================================
// Reassembly result
// ============================================================

enum class ReassemblyResult
{
    OK,
    NOT_TARGET,
    BROKEN_FLOW
};


// ============================================================
// TCP sequence comparison
// ============================================================

bool tcp_seq_before(uint32_t a, uint32_t b);
bool tcp_seq_after(uint32_t a, uint32_t b);


// ============================================================
// TCP reassembly
// ============================================================

ReassemblyResult feed_tcp_reassembly(const Flow_Key& key, Flow_Entry& flow, uint32_t seq, const uint8_t* payload, size_t payload_len);
ReassemblyResult store_out_of_order_segment(const Flow_Key& key, Flow_Entry& flow, uint32_t seq, const uint8_t* payload, size_t payload_len);
ReassemblyResult drain_contiguous_out_of_order_segments(const Flow_Key& key, Flow_Entry& flow);
ReassemblyResult append_to_tls_record_buffer(const Flow_Key& key, Flow_Entry& flow, const uint8_t* data, size_t data_len);


// ============================================================
// TLS Record reassembly
// ============================================================

ReassemblyResult try_parse_tls_records(const Flow_Key& key, Flow_Entry& flow);
ReassemblyResult push_tls_record_queue(const Flow_Key& key, Flow_Entry& flow, const TLS_Record& record);
void notify_ready_flow(const Flow_Key& key);


// ============================================================
// packet handling
// ============================================================

void handle_captured_packet(const uint8_t* packet, size_t packet_len);