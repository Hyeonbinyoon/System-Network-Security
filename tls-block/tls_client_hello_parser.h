#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>


// ============================================================
// ClientHello parse result
// ============================================================

enum class ClientHelloParseResult
{
    TARGET_MATCH,
    NOT_TARGET,
    NO_SNI,
    BROKEN_CLIENT_HELLO
};


// ============================================================
// TLS ClientHello constants
// ============================================================

#define TLS_CLIENT_HELLO_HANDSHAKE_TYPE        0x01
#define TLS_CLIENT_HELLO_HANDSHAKE_HEADER_SIZE 4

#define TLS_CLIENT_HELLO_LEGACY_VERSION_SIZE   2
#define TLS_CLIENT_HELLO_RANDOM_SIZE           32

#define TLS_EXTENSION_SERVER_NAME              0x0000
#define TLS_SERVER_NAME_TYPE_HOST_NAME         0x00


// ============================================================
// TLS ClientHello helpers
// ============================================================

uint16_t read_tls_u16(const uint8_t* data);
uint32_t client_hello_body_length(const uint8_t* handshake_header);


// ============================================================
// TLS ClientHello parser
// ============================================================

ClientHelloParseResult parse_client_hello_sni(const std::vector<uint8_t>& handshake_message);
ClientHelloParseResult parse_tls_extensions(const uint8_t* extensions, size_t extensions_len);
ClientHelloParseResult parse_sni_extension(const uint8_t* extension_data, size_t extension_len);