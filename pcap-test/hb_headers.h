#ifndef __HB_HEADERS_H
#define __HB_HEADERS_H

#include <stdint.h>

//header sizes

#define HB_ETH_H_SIZE            0x0e    /* Ethernet header:     14 bytes */
#define HB_IPV4_H_SIZE           0x14    /* IPv4 header:         20 bytes */
#define HB_TCP_H_SIZE            0x14    /* TCP header:          20 bytes */



//Ethernet

#define MAC_ADDR_LEN             0x06    /* ethernet adderes length: 6 bytes */
#define ETH_OFFSET_DST_MAC       0x00
#define ETH_OFFSET_SRC_MAC       0x06
#define ETH_OFFSET_ETHERTYPE     0x0c
#define ETHERTYPE_IPV4           0x0800  /* IPV4 protocol */



//IP

#define IP_OFFSET_VERSION_IHL    0x00    /* Version: 1 nibble, IHL: 1 nibble */
#define IP_OFFSET_TOTAL_LEN      0x02
#define IP_OFFSET_PROTOCOL       0x09
#define IP_OFFSET_SRC_IP         0x0c
#define IP_OFFSET_DST_IP         0x10

#define IP_PROTOCOL_TCP          0x06
#define IP_FLAG_MF               0x2000
#define IP_FRAG_OFFSET_MASK      0x1FFF



//TCP

#define TCP_OFFSET_SRC_PORT      0x00
#define TCP_OFFSET_DST_PORT      0x02
#define TCP_OFFSET_HDR_LEN       0x0c    /* TCP Header Length: 1 nibble */



#pragma pack(push, 1)

typedef struct ethernet_header {

	uint8_t dst_mac[MAC_ADDR_LEN];
	uint8_t src_mac[MAC_ADDR_LEN];
	uint16_t ethertype;

} hb_eth_hdr;



typedef struct ip_header {

	uint8_t ver_and_hdr_len;
	uint8_t tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t hdr_checksum;
	uint32_t src_ip;
	uint32_t dst_ip;

} hb_ip_hdr;



typedef struct tcp_header {

	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t hdr_len_and_reserved;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_p;
} hb_tcp_hdr;

#pragma pack(pop)
#endif

