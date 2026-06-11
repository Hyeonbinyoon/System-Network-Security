#include "hb-headers.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <pcap.h>

bool parse_eth(const u_char* packet, uint32_t packet_len, hb_eth_hdr* eth) {
	
	if (packet == NULL || eth == NULL) return false;
	if (packet_len < HB_ETH_H_SIZE) return false;
	
	uint16_t ethertype;

	memcpy(eth->dst_mac, packet + ETH_OFFSET_DST_MAC, MAC_ADDR_LEN);
	memcpy(eth->src_mac, packet + ETH_OFFSET_SRC_MAC, MAC_ADDR_LEN);
	memcpy(&ethertype, packet + ETH_OFFSET_ETHERTYPE, sizeof(ethertype));
	
	eth->ethertype = ntohs(ethertype); 
	
	return true; 
}



bool parse_ip(const u_char* packet, uint32_t packet_len, hb_eth_hdr eth, hb_ip_hdr* ip) {
	
	if (!(eth.ethertype == ETHERTYPE_IP)) return false;
	if (ip == NULL) return false;
	if (packet_len < HB_ETH_H_SIZE + HB_IPV4_H_SIZE) return false;
	
	const u_char* ip_packet = packet + HB_ETH_H_SIZE;

	uint8_t ver_and_ihl;
	uint16_t total_len;
	uint32_t src_ip;
	uint32_t dst_ip;


	memcpy(&ver_and_ihl,ip_packet + IP_OFFSET_VERSION_IHL, sizeof(ver_and_ihl));
	memcpy(&total_len, ip_packet + IP_OFFSET_TOTAL_LEN, sizeof(total_len));
	memcpy(&ip->protocol, ip_packet + IP_OFFSET_PROTOCOL, sizeof(ip->protocol));
	memcpy(&src_ip, ip_packet + IP_OFFSET_SRC_IP, sizeof(src_ip));
	memcpy(&dst_ip, ip_packet + IP_OFFSET_DST_IP, sizeof(dst_ip));


	ip->version = ver_and_ihl >> 4;
	if (ip->version != 4) return false;

	ip->hdr_len = (ver_and_ihl & 0x0f) * 4;
	ip->total_len = ntohs(total_len);
	ip->src_ip = ntohl(src_ip);
	ip->dst_ip = ntohl(dst_ip);


	return true;
}



bool parse_tcp(const u_char* packet, uint32_t packet_len, hb_ip_hdr ip, hb_tcp_hdr* tcp) {
	
	if (!(ip.protocol == IP_PROTOCOL_TCP)) return false;
        if (tcp == NULL) return false;
        if (packet_len < HB_ETH_H_SIZE + ip.hdr_len + HB_TCP_H_SIZE) return false;


	const u_char* tcp_packet = packet + HB_ETH_H_SIZE + ip.hdr_len;

	uint16_t src_port;
	uint16_t dst_port;
	uint8_t thl_and_reserved;


	memcpy(&src_port, tcp_packet + TCP_OFFSET_SRC_PORT, sizeof(src_port));
	memcpy(&dst_port, tcp_packet + TCP_OFFSET_DST_PORT, sizeof(dst_port));
	memcpy(&thl_and_reserved, tcp_packet + TCP_OFFSET_HDR_LEN, sizeof(thl_and_reserved));
 
	tcp->src_port = ntohs(src_port);
        tcp->dst_port = ntohs(dst_port);
	tcp->hdr_len = (thl_and_reserved >> 4) * 4;
	

	tcp->payload_len = ip.total_len - (ip.hdr_len + tcp->hdr_len);
	if (tcp->payload_len == 0) tcp ->payload = NULL;
	else tcp->payload = tcp_packet + tcp->hdr_len;

	return true;
	}




