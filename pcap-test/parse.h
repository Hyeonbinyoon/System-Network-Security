#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>
#include "hb-headers.h"

bool parse_eth(const u_char* packet, uint32_t packet_len, hb_eth_hdr* eth);

bool parse_ip(const u_char* packet, uint32_t packet_len, hb_eth_hdr eth, hb_ip_hdr* ip);

bool parse_tcp(const u_char* packet, uint32_t packet_len, hb_ip_hdr ip, hb_tcp_hdr* tcp);


#endif

