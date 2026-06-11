//arp_utils.h
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

#pragma pack(push, 1)
struct EthIpPacket {
    hb_eth_hdr eth;
    hb_ip_hdr ip;
};
#pragma pack(pop)


typedef struct Flow {
    uint32_t sender_ip;
    hb_mac   sender_mac;

    uint32_t target_ip;
    hb_mac   target_mac;

    struct Flow* next;
} Flow;

typedef enum {
    FLOW_PACKET_NONE = 0,
    FLOW_PACKET_SENDER_BROADCAST_REQ,
    FLOW_PACKET_SENDER_UNICAST_REQ_TO_ME,
    FLOW_PACKET_TARGET_BROADCAST_REQ
} FlowPacketType;


void usage(void);

bool get_my_mac(const char* ifname, hb_mac* mac);
bool get_my_ip(const char* ifname, uint32_t* ip);
bool get_other_mac(pcap_t* pcap, hb_mac my_mac, uint32_t my_ip, hb_mac* other_mac, uint32_t other_ip);

// 문자열 IP 하나를 검증하고 network byte order uint32_t로 변환
bool get_ip_from_string(const char* ip_str, uint32_t* ip);

bool send_arp_reply(pcap_t* pcap, hb_mac sender_mac, uint32_t sender_ip, hb_mac target_mac, uint32_t traget_ip);
bool send_arp_infect_reply(pcap_t* pcap, hb_mac sender_mac, uint32_t sender_ip, hb_mac my_mac, uint32_t target_ip);

Flow* create_flow(uint32_t sender_ip, hb_mac sender_mac, uint32_t target_ip, hb_mac target_mac);
bool append_flow(Flow** head, Flow* node);
void free_flow_list(Flow* head);

bool check_sender_broadcast_arp_request(const struct EthArpPacket* packet, const Flow* flow);
bool check_sender_unicast_arp_request_to_me(const struct EthArpPacket* packet, const Flow* flow, hb_mac my_mac);
bool check_target_broadcast_arp_request(const struct EthArpPacket* packet, const Flow* flow);


Flow* find_flow_from_arp_request(Flow* head, const struct EthArpPacket* packet, hb_mac my_mac, FlowPacketType* type);
Flow* find_flow_from_ip_packet(Flow* head, const struct EthIpPacket* packet, uint32_t my_ip);

#endif
