#include "tls_client_hello_parser.h"
#include "common.h"

#include <algorithm>
#include <cctype>
#include <string>


// ============================================================
// Internal cursor helper
// ============================================================

struct TLSCursor
{
    const uint8_t* data = nullptr;
    size_t len = 0;
    size_t offset = 0;

    bool has(size_t need) const
    {
        if(data == nullptr) return false;
        if(offset > len) return false;
        return need <= len - offset;
    }

    bool read_u8(uint8_t* value)
    {
        if(value == nullptr) return false;
        if(!has(1)) return false;

        *value = data[offset];
        offset += 1;
        return true;
    }

    bool read_u16(uint16_t* value)
    {
        if(value == nullptr) return false;
        if(!has(2)) return false;

        *value = read_tls_u16(data + offset);
        offset += 2;
        return true;
    }

    bool skip(size_t size)
    {
        if(!has(size)) return false;

        offset += size;
        return true;
    }

    const uint8_t* current() const
    {
        if(data == nullptr) return nullptr;
        return data + offset;
    }

    size_t remaining() const
    {
        if(offset > len) return 0;
        return len - offset;
    }
};


static ClientHelloParseResult broken_client_hello(const char* message)
{
    ERROR_LOG("%s", message);

    return ClientHelloParseResult::BROKEN_CLIENT_HELLO;
}


// ============================================================
// TLS ClientHello helpers
// ============================================================

static std::string normalize_domain_name(std::string domain_name)
{
    while(!domain_name.empty() && domain_name.back() == '.')
        domain_name.pop_back();

    std::transform(domain_name.begin(),
                   domain_name.end(),
                   domain_name.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });

    return domain_name;
}


static bool domain_matches_target(const std::string& server_name, const std::string& target_name)
{
    std::string normalized_server_name = normalize_domain_name(server_name);
    std::string normalized_target_name = normalize_domain_name(target_name);

    if(normalized_server_name.empty() || normalized_target_name.empty())
        return false;

    if(normalized_server_name == normalized_target_name)
        return true;

    if(normalized_server_name.size() <= normalized_target_name.size())
        return false;

    size_t suffix_pos = normalized_server_name.size() - normalized_target_name.size();

    if(normalized_server_name.compare(suffix_pos, normalized_target_name.size(), normalized_target_name) != 0)
        return false;

    return normalized_server_name[suffix_pos - 1] == '.';
}


uint16_t read_tls_u16(const uint8_t* data)
{
    uint16_t value = 0;

    value |= static_cast<uint16_t>(data[0]) << 8;
    value |= static_cast<uint16_t>(data[1]);

    return value;
}


uint32_t client_hello_body_length(const uint8_t* handshake_header)
{
    uint32_t length = 0;

    length |= static_cast<uint32_t>(handshake_header[1]) << 16;
    length |= static_cast<uint32_t>(handshake_header[2]) << 8;
    length |= static_cast<uint32_t>(handshake_header[3]);

    return length;
}


// ============================================================
// TLS ClientHello parser
// ============================================================

ClientHelloParseResult parse_client_hello_sni(const std::vector<uint8_t>& handshake_message)
{
    const uint8_t* data = handshake_message.data();
    size_t total_len = handshake_message.size();

    TLSCursor cursor{data, total_len, 0};

    if(!cursor.has(TLS_CLIENT_HELLO_HANDSHAKE_HEADER_SIZE))
        return broken_client_hello("ClientHello handshake header is too short");

    if(data[0] != TLS_CLIENT_HELLO_HANDSHAKE_TYPE)
        return broken_client_hello("not a ClientHello handshake message");

    uint32_t handshake_body_len = client_hello_body_length(data);

    if(total_len != TLS_CLIENT_HELLO_HANDSHAKE_HEADER_SIZE + static_cast<size_t>(handshake_body_len))
        return broken_client_hello("ClientHello handshake body length mismatch");

    cursor.offset = TLS_CLIENT_HELLO_HANDSHAKE_HEADER_SIZE;

    if(!cursor.skip(TLS_CLIENT_HELLO_LEGACY_VERSION_SIZE))
        return broken_client_hello("ClientHello legacy_version is missing");

    if(!cursor.skip(TLS_CLIENT_HELLO_RANDOM_SIZE))
        return broken_client_hello("ClientHello random is missing");

    uint8_t session_id_len = 0;

    if(!cursor.read_u8(&session_id_len))
        return broken_client_hello("ClientHello session_id_length is missing");

    if(!cursor.skip(session_id_len))
        return broken_client_hello("ClientHello session_id length is out of range");

    uint16_t cipher_suites_len = 0;

    if(!cursor.read_u16(&cipher_suites_len))
        return broken_client_hello("ClientHello cipher_suites_length is missing");

    if(cipher_suites_len == 0 || (cipher_suites_len % 2) != 0) // cipher_suites 필드는 2바이트짜리 CipherSuite 값들의 배열
        return broken_client_hello("ClientHello cipher_suites_length is invalid");

    if(!cursor.skip(cipher_suites_len))
        return broken_client_hello("ClientHello cipher_suites length is out of range");

    uint8_t compression_methods_len = 0;

    if(!cursor.read_u8(&compression_methods_len))
        return broken_client_hello("ClientHello compression_methods_length is missing");

    if(compression_methods_len == 0)
        return broken_client_hello("ClientHello compression_methods_length is invalid");

    if(!cursor.skip(compression_methods_len))
        return broken_client_hello("ClientHello compression_methods length is out of range");

    if(cursor.offset == total_len)
    {
        DEBUG_LOG("ClientHello has no extensions");
        return ClientHelloParseResult::NO_SNI;
    }

    uint16_t extensions_len = 0;

    if(!cursor.read_u16(&extensions_len))
        return broken_client_hello("ClientHello extensions_length is missing");

    if(!cursor.has(extensions_len))
        return broken_client_hello("ClientHello extensions length is out of range");

    const uint8_t* extensions_start = cursor.current();

    if(!cursor.skip(extensions_len))
        return broken_client_hello("ClientHello extensions skip failed");

    if(cursor.offset != total_len)
        return broken_client_hello("ClientHello extensions_length mismatch");

    return parse_tls_extensions(extensions_start, extensions_len);
}


ClientHelloParseResult parse_tls_extensions(const uint8_t* extensions, size_t extensions_len)
{
    if(extensions_len == 0)
    {
        DEBUG_LOG("ClientHello extensions block is empty");
        return ClientHelloParseResult::NO_SNI;
    }

    TLSCursor cursor{extensions, extensions_len, 0};

    while(cursor.offset < cursor.len)
    {
        uint16_t extension_type = 0;
        uint16_t extension_len = 0;

        if(!cursor.read_u16(&extension_type))
            return broken_client_hello("TLS extension type is missing");

        if(!cursor.read_u16(&extension_len))
            return broken_client_hello("TLS extension length is missing");

        if(!cursor.has(extension_len))
            return broken_client_hello("TLS extension length is out of range");

        const uint8_t* extension_data = cursor.current();

        if(extension_type == TLS_EXTENSION_SERVER_NAME)
            return parse_sni_extension(extension_data, extension_len);

        if(!cursor.skip(extension_len))
            return broken_client_hello("TLS extension skip failed");
    }

    DEBUG_LOG("ClientHello SNI extension not found");

    return ClientHelloParseResult::NO_SNI;
}


ClientHelloParseResult parse_sni_extension(const uint8_t* extension_data, size_t extension_len)
{
    TLSCursor cursor{extension_data, extension_len, 0};

    uint16_t server_name_list_len = 0;

    if(!cursor.read_u16(&server_name_list_len))
        return broken_client_hello("SNI server_name_list_length is missing");

    if(server_name_list_len == 0)
        return broken_client_hello("SNI server_name_list_length is zero");

    if(server_name_list_len != cursor.remaining())
        return broken_client_hello("SNI server_name_list_length mismatch");

    while(cursor.offset < cursor.len) // ServerName entry가 여려 개 있는 경우를 커버
    {
        uint8_t server_name_type = 0;
        uint16_t server_name_len = 0;

        if(!cursor.read_u8(&server_name_type))
            return broken_client_hello("SNI server_name_type is missing");

        if(!cursor.read_u16(&server_name_len))
            return broken_client_hello("SNI server_name_length is missing");

        if(server_name_len == 0)
            return broken_client_hello("SNI server_name length is zero");

        if(!cursor.has(server_name_len))
            return broken_client_hello("SNI server_name length is out of range");

        if(server_name_type == TLS_SERVER_NAME_TYPE_HOST_NAME)
        {
            std::string server_name(reinterpret_cast<const char*>(cursor.current()), server_name_len);

            DEBUG_LOG("SNI host_name: %s", server_name.c_str());

            if(domain_matches_target(server_name, target_server_name))
                return ClientHelloParseResult::TARGET_MATCH;

            return ClientHelloParseResult::NOT_TARGET;
        }

        if(!cursor.skip(server_name_len))
            return broken_client_hello("SNI server_name skip failed");
    }

    DEBUG_LOG("SNI extension has no host_name entry");

    return ClientHelloParseResult::NO_SNI;
}