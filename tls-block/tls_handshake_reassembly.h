#pragma once

#include "flow.h"

#include <cstddef>
#include <cstdint>


// ============================================================
// Handshake reassembly result
// ============================================================

enum class HandshakeReassemblyResult
{
    OK,
    NOT_TARGET,
    BROKEN_FLOW,
    BLOCKED_BY_SNI
};


// ============================================================
// TLS Handshake constants
// ============================================================

#define TLS_RECORD_TYPE_HANDSHAKE 0x16

#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01
#define TLS_HANDSHAKE_HEADER_SIZE 4


// ============================================================
// TLS Handshake helpers
// ============================================================

uint16_t tls_record_body_length(const TLS_Record& record);
uint32_t tls_handshake_body_length(const uint8_t* handshake_header);

bool is_handshake_record(const TLS_Record& record);
bool is_handshake_assembling(const Flow_Entry& flow);

void reset_tls_handshake_state(Flow_Entry& flow);


// ============================================================
// TLS Handshake reassembly
// ============================================================

HandshakeReassemblyResult process_ready_flow(const Flow_Key& key, Flow_Entry& flow);
HandshakeReassemblyResult process_tls_record_for_handshake(const Flow_Key& key, Flow_Entry& flow, const TLS_Record& record);
HandshakeReassemblyResult process_tls_record_body(const Flow_Key& key, Flow_Entry& flow, const uint8_t* record_body, size_t record_body_len);

HandshakeReassemblyResult consume_handshake_header(const Flow_Key& key, Flow_Entry& flow, const uint8_t* record_body, size_t record_body_len, size_t* record_body_offset);
HandshakeReassemblyResult consume_handshake_body(const Flow_Key& key, Flow_Entry& flow, const uint8_t* record_body, size_t record_body_len, size_t* record_body_offset);

HandshakeReassemblyResult handle_complete_handshake_message(const Flow_Key& key, Flow_Entry& flow);