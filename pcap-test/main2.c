#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include "hb_headers.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test ens33\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = { .dev_ = NULL };


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


int main(int argc, char* argv[]) {
	int i = 1;
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}


	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		const hb_eth_hdr* eth;
		const hb_ip_hdr* ip;
		const hb_tcp_hdr* tcp;

		uint8_t ip_hdr_len;
		uint8_t tcp_hdr_len;
		uint16_t payload_len;
		uint16_t print_len;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		// Ethernet
		if(header->caplen < HB_ETH_H_SIZE) continue;


		eth = (const hb_eth_hdr*)packet;		
		
		if(ntohs(eth->ethertype) != ETHERTYPE_IPV4) continue;
		if(header->caplen < HB_ETH_H_SIZE + HB_IPV4_H_SIZE) continue;


		// IP
		ip = (const hb_ip_hdr*)(packet + HB_ETH_H_SIZE);
		
		if((ip->ver_and_hdr_len >> 4) != 4) continue;	
		if(ip->protocol != IP_PROTOCOL_TCP) continue;
		if (((ntohs(ip->offset) & IP_FLAG_MF) != 0) || ((ntohs(ip->offset) & IP_FRAG_OFFSET_MASK) != 0)) continue; // Skip fragmented IPv4 packets

		ip_hdr_len = (ip->ver_and_hdr_len & 0x0F) * 4;
		if (ip_hdr_len < HB_IPV4_H_SIZE) continue;
		if(header->caplen < HB_ETH_H_SIZE + ip_hdr_len + HB_TCP_H_SIZE) continue;
		
		
		// TCP
		tcp = (const hb_tcp_hdr*)(packet + HB_ETH_H_SIZE + ip_hdr_len);

		tcp_hdr_len = (tcp->hdr_len_and_reserved >> 4) * 4;
		if (tcp_hdr_len < HB_TCP_H_SIZE) continue;
		if (header->caplen < HB_ETH_H_SIZE + ip_hdr_len + tcp_hdr_len) continue;

		if (ntohs(ip->total_len) < ip_hdr_len + tcp_hdr_len) continue;
		if (header->caplen < HB_ETH_H_SIZE + ntohs(ip->total_len)) {payload_len = header->caplen - (HB_ETH_H_SIZE + ip_hdr_len + tcp_hdr_len);}
		else {payload_len = ntohs(ip->total_len) - (ip_hdr_len + tcp_hdr_len);}
		print_len = (payload_len <= 20) ? payload_len : 20;


		

		printf("packet num%d\n", i++);
		printf("dst_mac --> %02x:%02x:%02x:%02x:%02x:%02x\n", eth->dst_mac[0], eth->dst_mac[1] ,eth->dst_mac[2], eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);

		printf("src_mac --> %02x:%02x:%02x:%02x:%02x:%02x\n", eth->src_mac[0], eth->src_mac[1] ,eth->src_mac[2], eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
		
		printf("src_ip --> %u.%u.%u.%u\n", 
				(ntohl(ip->src_ip) & 0xFF000000) >> 24, (ntohl(ip->src_ip) & 0x00FF0000) >> 16, (ntohl(ip->src_ip) & 0x0000FF00) >> 8, (ntohl(ip->src_ip) & 0x000000FF));

		printf("dst_ip --> %u.%u.%u.%u\n", 
				(ntohl(ip->dst_ip) & 0xFF000000) >> 24, (ntohl(ip->dst_ip) & 0x00FF0000) >> 16, (ntohl(ip->dst_ip) & 0x0000FF00) >> 8, (ntohl(ip->dst_ip) & 0x000000FF));
		
		printf("src_port --> %u\n", ntohs(tcp->src_port));

		printf("dst_port --> %u\n", ntohs(tcp->dst_port));
		
		if(payload_len != 0) {

			printf("payload --> ");
			for(int i=0; i<print_len; i++){
				 printf("%02x|",packet [i + HB_ETH_H_SIZE + ip_hdr_len + tcp_hdr_len]);}}

		printf("\n\n");
	
	}
	pcap_close(pcap);

}

