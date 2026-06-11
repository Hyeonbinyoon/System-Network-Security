//http_parser.h
#ifndef __HTTP_PARSER_H
#define __HTTP_PARSER_H

#include <optional>
#include <string>

bool Http_is_request(const std::string& payload);
std::optional<std::string> Http_extract_host(const std::string& payload);

#endif
