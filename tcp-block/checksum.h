#pragma once

#include "hb_headers.h"

#include <stdint.h>

uint16_t ip_checksum(hb_ip_hdr* ip);

uint16_t tcp_checksum(const hb_ip_hdr* ip, const hb_tcp_hdr* tcp, const uint8_t* data, uint32_t data_len);