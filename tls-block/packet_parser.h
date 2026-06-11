#pragma once

#include "flow.h"
#include "hb_headers.h"

#include <cstddef>
#include <cstdint>


// ============================================================
// Packet parsing
// ============================================================

bool parse_packet_headers(const uint8_t* packet, size_t packet_len,
                          const hb_eth_hdr** eth_hdr,
                          const hb_ip_hdr** ip_hdr,
                          const hb_tcp_hdr** tcp_hdr,
                          const uint8_t** tcp_payload,
                          size_t* tcp_payload_len);


// ============================================================
// Direction check
// ============================================================

bool is_client_to_server(const Flow_Entry& flow, const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr);
bool is_server_to_client(const Flow_Entry& flow, const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr);