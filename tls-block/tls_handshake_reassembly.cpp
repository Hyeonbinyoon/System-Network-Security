#include "tls_handshake_reassembly.h"
#include "tls_client_hello_parser.h"

#include <algorithm>
#include <utility>


// ============================================================
// TLS Handshake helpers
// ============================================================

uint16_t tls_record_body_length(const TLS_Record& record)
{
    uint16_t length = 0;

    length |= static_cast<uint16_t>(record.header[3]) << 8;
    length |= static_cast<uint16_t>(record.header[4]);

    return length;
}


uint32_t tls_handshake_body_length(const uint8_t* handshake_header)
{
    uint32_t length = 0;

    length |= static_cast<uint32_t>(handshake_header[1]) << 16;
    length |= static_cast<uint32_t>(handshake_header[2]) << 8;
    length |= static_cast<uint32_t>(handshake_header[3]);

    return length;
}


bool is_handshake_record(const TLS_Record& record)
{
    return record.header[0] == TLS_RECORD_TYPE_HANDSHAKE;
}


bool is_handshake_assembling(const Flow_Entry& flow)
{
    if(flow.handshake_assemble_state == HandshakeAssembleState::WAIT_HANDSHAKE_BODY)
        return true;

    if(!flow.tls_handshake_buffer.empty())
        return true;

    return false;
}


void reset_tls_handshake_state(Flow_Entry& flow)
{
    flow.tls_handshake_buffer.clear();

    flow.handshake_assemble_state = HandshakeAssembleState::WAIT_HANDSHAKE_HEADER;

    flow.current_handshake_type = 0;
    flow.expected_handshake_body_len = 0;
    flow.accumulated_handshake_body_len = 0;
}


// ============================================================
// TLS Handshake reassembly
// ============================================================

HandshakeReassemblyResult process_ready_flow(const Flow_Key& key, Flow_Entry& flow)
{
    while(!flow.tls_record_queue.empty())
    {
        TLS_Record record = std::move(flow.tls_record_queue.front());
        flow.tls_record_queue.pop();

        HandshakeReassemblyResult result = process_tls_record_for_handshake(key, flow, record);

        if(result != HandshakeReassemblyResult::OK)
            return result;
    }

    return HandshakeReassemblyResult::OK;
}


HandshakeReassemblyResult process_tls_record_for_handshake(const Flow_Key& key, Flow_Entry& flow, const TLS_Record& record)
{
    uint16_t record_body_len = tls_record_body_length(record);

    if(record_body_len != record.body.size())
    {
        ERROR_LOG("TLS record body length mismatch");
        return HandshakeReassemblyResult::BROKEN_FLOW;
    } // 1단계에서 완성된 TLS Record라도, header length와 실제 body size가 다르면 구조적으로 비정상

    if(!is_handshake_record(record))
    {
        if(is_handshake_assembling(flow))
        {
            ERROR_LOG("non-handshake record appeared during handshake assembly");
            return HandshakeReassemblyResult::BROKEN_FLOW;
        } // Handshake 조립 중간에 다른 Record Type이 끼어들면 fragmentation 흐름이 깨진 것으로 판단

        DEBUG_LOG("non-handshake record ignored as not target");
        return HandshakeReassemblyResult::NOT_TARGET;
    }

    return process_tls_record_body(key, flow, record.body.data(), record.body.size());
}


HandshakeReassemblyResult process_tls_record_body(const Flow_Key& key, Flow_Entry& flow, const uint8_t* record_body, size_t record_body_len)
{
    if(record_body_len == 0) return HandshakeReassemblyResult::OK;
    if(record_body == nullptr) return HandshakeReassemblyResult::BROKEN_FLOW;

    size_t record_body_offset = 0;

    while(record_body_offset < record_body_len)
    {
        if(flow.handshake_assemble_state == HandshakeAssembleState::WAIT_HANDSHAKE_HEADER)
        {
            HandshakeReassemblyResult header_result =
                consume_handshake_header(key, flow, record_body, record_body_len, &record_body_offset);

            if(header_result != HandshakeReassemblyResult::OK)
                return header_result;
        }

        if(flow.handshake_assemble_state == HandshakeAssembleState::WAIT_HANDSHAKE_BODY)
        {
            HandshakeReassemblyResult body_result =
                consume_handshake_body(key, flow, record_body, record_body_len, &record_body_offset);

            if(body_result != HandshakeReassemblyResult::OK)
                return body_result;
        }
    }

    return HandshakeReassemblyResult::OK;
}


HandshakeReassemblyResult consume_handshake_header(const Flow_Key& key, Flow_Entry& flow, const uint8_t* record_body, size_t record_body_len, size_t* record_body_offset)
{
    (void)key;

    if(record_body == nullptr) return HandshakeReassemblyResult::BROKEN_FLOW;
    if(record_body_offset == nullptr) return HandshakeReassemblyResult::BROKEN_FLOW;
    if(*record_body_offset > record_body_len) return HandshakeReassemblyResult::BROKEN_FLOW;

    if(flow.tls_handshake_buffer.size() > TLS_HANDSHAKE_HEADER_SIZE)
    {
        ERROR_LOG("invalid TLS handshake header buffer state");
        return HandshakeReassemblyResult::BROKEN_FLOW;
    }

    size_t needed_header_len = TLS_HANDSHAKE_HEADER_SIZE - flow.tls_handshake_buffer.size();
    size_t available_len = record_body_len - *record_body_offset;
    size_t copy_len = std::min(needed_header_len, available_len);

    flow.tls_handshake_buffer.insert(flow.tls_handshake_buffer.end(),
                                     record_body + *record_body_offset,
                                     record_body + *record_body_offset + copy_len);

    *record_body_offset += copy_len;

    if(flow.tls_handshake_buffer.size() < TLS_HANDSHAKE_HEADER_SIZE)
        return HandshakeReassemblyResult::OK; // Handshake Header 일부만 모인 상태이므로 다음 TLS Record를 기다림

    flow.current_handshake_type = flow.tls_handshake_buffer[0];
    flow.expected_handshake_body_len = tls_handshake_body_length(flow.tls_handshake_buffer.data());
    flow.accumulated_handshake_body_len = 0;

    flow.handshake_assemble_state = HandshakeAssembleState::WAIT_HANDSHAKE_BODY;

    return HandshakeReassemblyResult::OK;
}


HandshakeReassemblyResult consume_handshake_body(const Flow_Key& key, Flow_Entry& flow, const uint8_t* record_body, size_t record_body_len, size_t* record_body_offset)
{
    if(record_body == nullptr) return HandshakeReassemblyResult::BROKEN_FLOW;
    if(record_body_offset == nullptr) return HandshakeReassemblyResult::BROKEN_FLOW;
    if(*record_body_offset > record_body_len) return HandshakeReassemblyResult::BROKEN_FLOW;

    if(flow.accumulated_handshake_body_len > flow.expected_handshake_body_len)
    {
        ERROR_LOG("invalid TLS handshake body length state");
        return HandshakeReassemblyResult::BROKEN_FLOW;
    }

    uint32_t remaining_body_len = flow.expected_handshake_body_len - flow.accumulated_handshake_body_len;
    size_t available_len = record_body_len - *record_body_offset;
    size_t copy_len = std::min(static_cast<size_t>(remaining_body_len), available_len);

    flow.tls_handshake_buffer.insert(flow.tls_handshake_buffer.end(),
                                     record_body + *record_body_offset,
                                     record_body + *record_body_offset + copy_len);

    *record_body_offset += copy_len;
    flow.accumulated_handshake_body_len += static_cast<uint32_t>(copy_len);

    if(flow.accumulated_handshake_body_len < flow.expected_handshake_body_len)
        return HandshakeReassemblyResult::OK; // Handshake Body가 아직 덜 모였으므로 다음 TLS Record를 기다림

    return handle_complete_handshake_message(key, flow);
}


HandshakeReassemblyResult handle_complete_handshake_message(const Flow_Key& key, Flow_Entry& flow)
{
    (void)key;

    if(flow.tls_handshake_buffer.size() != TLS_HANDSHAKE_HEADER_SIZE + flow.expected_handshake_body_len)
    {
        ERROR_LOG("completed TLS handshake message length mismatch");
        return HandshakeReassemblyResult::BROKEN_FLOW;
    }

    if(flow.current_handshake_type == TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    {
        DEBUG_LOG("complete ClientHello handshake message assembled");

        ClientHelloParseResult parse_result = parse_client_hello_sni(flow.tls_handshake_buffer);

        reset_tls_handshake_state(flow);

        if(parse_result == ClientHelloParseResult::TARGET_MATCH)
        {
            DEBUG_LOG("target SNI matched");
            return HandshakeReassemblyResult::BLOCKED_BY_SNI;
        }

        if(parse_result == ClientHelloParseResult::NOT_TARGET)
        {
            DEBUG_LOG("SNI is not target");
            return HandshakeReassemblyResult::NOT_TARGET;
        }

        if(parse_result == ClientHelloParseResult::NO_SNI)
        {
            DEBUG_LOG("ClientHello has no target SNI");
            return HandshakeReassemblyResult::NOT_TARGET;
        }

        return HandshakeReassemblyResult::BROKEN_FLOW;
    }

    DEBUG_LOG("non-ClientHello handshake message ignored");

    reset_tls_handshake_state(flow);

    return HandshakeReassemblyResult::OK;
}