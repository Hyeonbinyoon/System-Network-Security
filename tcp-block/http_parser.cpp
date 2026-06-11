//http_parser.cpp
#include "http_parser.h"
#include <optional>
#include <string>


bool Http_is_request(const std::string& payload)
{
    const char* methods[] = {
        "GET ",
        "POST ",
        "HEAD ",
        "PUT ",
        "DELETE ",
        "OPTIONS ",
        "PATCH ",
        "CONNECT ",
        "TRACE "
    };

    for (const char* method : methods)
    {
        if (payload.rfind(method, 0) == 0) return true;
    }

    return false;
}



std::optional<std::string> Http_extract_host(const std::string& payload)
{
    if (!Http_is_request(payload)) return std::nullopt;

    size_t line_begin = 0;

    while (line_begin < payload.size())
    {
        size_t line_end = payload.find("\r\n", line_begin);
        if (line_end == std::string::npos) return std::nullopt;

        std::string line = payload.substr(line_begin, line_end - line_begin);
        if (line.rfind("Host: ", 0) == 0) return line.substr(6);

        line_begin = line_end + 2;
    }

    return std::nullopt;
}
