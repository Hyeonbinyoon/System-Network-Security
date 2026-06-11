//hb_headers.h
#ifndef __HB_HEADERS_H
#define __HB_HEADERS_H

#include <stdint.h>
#include <stdbool.h>


// ============================================================
// Header sizes
// ============================================================

#define HB_ETH_H_SIZE            0x0e    /* Ethernet header: 14 bytes */
#define HB_ARP_H_SIZE            0x1c    /* ARP header:      28 bytes */
#define HB_IPV4_H_SIZE           0x14    /* IPv4 header:     20 bytes */
#define HB_TCP_H_SIZE            0x14    /* TCP header:      20 bytes */



// ============================================================
// Ethernet
// ============================================================

#define MAC_ADDR_LEN             0x06    /* MAC address length: 6 bytes */

#define ETH_OFFSET_DST_MAC       0x00
#define ETH_OFFSET_SRC_MAC       0x06
#define ETH_OFFSET_ETHERTYPE     0x0c

#define ETHERTYPE_IPV4           0x0800
#define ETHERTYPE_ARP            0x0806



// ============================================================
// ARP
// ============================================================

#define ARP_HARDWARE_ETHERNET    0x0001
#define ARP_OPCODE_REQUEST       0x0001
#define ARP_OPCODE_REPLY         0x0002
#define ARP_PROTOCOL_ADDR_LEN_IP 0x04


// ============================================================
// IPv4
// ============================================================

#define IP_OFFSET_VERSION_IHL    0x00
#define IP_OFFSET_TOTAL_LEN      0x02
#define IP_OFFSET_PROTOCOL       0x09
#define IP_OFFSET_SRC_IP         0x0c
#define IP_OFFSET_DST_IP         0x10

#define IP_VERSION_IPv4          0x04
#define IP_PROTOCOL_TCP          0x06
#define IP_FLAG_MF               0x2000
#define IP_FRAG_OFFSET_MASK      0x1FFF



// ============================================================
// TCP
// ============================================================

#define TCP_OFFSET_SRC_PORT      0x00
#define TCP_OFFSET_DST_PORT      0x02
#define TCP_OFFSET_HDR_LEN       0x0c



#pragma pack(push, 1)

typedef struct mac_address {
    uint8_t bytes[MAC_ADDR_LEN];
} hb_mac;


typedef struct ethernet_header {
    hb_mac   dst_mac;
    hb_mac   src_mac;
    uint16_t ethertype;
} hb_eth_hdr;


typedef struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_addr_len;
    uint8_t  protocol_addr_len;
    uint16_t opcode;
    hb_mac   sender_mac;
    uint32_t sender_ip;
    hb_mac   target_mac;
    uint32_t target_ip;
} hb_arp_hdr;


typedef struct ip_header {
    uint8_t  ver_and_hdr_len;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hdr_checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} hb_ip_hdr;


typedef struct tcp_header {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  hdr_len_and_reserved;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_p;
} hb_tcp_hdr;

#pragma pack(pop)



// ============================================================
// MAC / IP helper functions
// ============================================================

// Parse functions --> 사전에 Validation functions로 검증해야함
hb_mac   Mac_parse(const char* s);
uint32_t Ip_parse(const char* s);

// Validation functions
bool     Mac_is_valid_string(const char* s);
bool     Ip_is_valid_string(const char* s);

// Special MAC values
hb_mac   Mac_null(void);
hb_mac   Mac_broadcast(void);

// MAC tests
bool     Mac_is_null(hb_mac mac);
bool     Mac_is_broadcast(hb_mac mac);

#endif
