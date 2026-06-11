#ifndef __ARP_UTILS_H
#define __ARP_UTILS_H

#include <stdbool.h>
#include <stdint.h>
#include <pcap.h>
#include "hb_headers.h"

#pragma pack(push, 1)
struct EthArpPacket {
    hb_eth_hdr eth;
    hb_arp_hdr arp;
};
#pragma pack(pop)


void usage(void);

bool get_my_mac(const char* ifname, hb_mac* mac);
bool get_my_ip(const char* ifname, uint32_t* ip);

// 문자열 IP 하나를 검증하고 network byte order uint32_t로 변환
bool get_ip_from_string(const char* ip_str, uint32_t* ip);

bool get_other_mac(pcap_t* pcap,
                   hb_mac my_mac,
                   uint32_t my_ip,
                   uint32_t other_ip,
                   hb_mac* other_mac);

#endif
