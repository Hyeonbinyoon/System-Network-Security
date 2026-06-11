#pragma once

#include "hb_headers.h"

#include <pcap.h>
#include <stdint.h>
#include <string>

struct ParsedPacket
{
    const hb_eth_hdr* eth;
    const hb_ip_hdr* ip;
    const hb_tcp_hdr* tcp;

    const uint8_t* tcp_data;
    uint32_t tcp_data_size;
};

bool get_interface_mac(const char* interface, hb_mac* mac);

bool parse_packet(const struct pcap_pkthdr* header, const uint8_t* packet, ParsedPacket* parsed);

bool contains_pattern(const ParsedPacket& parsed, const std::string& pattern);

bool send_forward_rst(pcap_t* pcap_handle, const hb_mac& my_mac, const ParsedPacket& org);

bool send_backward_fin(int raw_socket, const ParsedPacket& org);