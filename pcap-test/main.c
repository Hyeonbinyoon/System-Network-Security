#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "hb-headers.h"
#include "parse.h"

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
		hb_eth_hdr eth;
		hb_ip_hdr ip;
		hb_tcp_hdr tcp;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		if(parse_eth(packet, header->caplen, &eth) == false) continue;
		if(parse_ip(packet, header->caplen, eth, &ip) == false) continue;
		if(parse_tcp(packet, header->caplen, ip, &tcp) == false) continue;


		printf("packet number%d\n", i++);
		printf("dst_mac --> %02x:%02x:%02x:%02x:%02x:%02x\n", eth.dst_mac[0], eth.dst_mac[1] ,eth.dst_mac[2], eth.dst_mac[3], eth.dst_mac[4], eth.dst_mac[5]);

		printf("src_mac --> %02x:%02x:%02x:%02x:%02x:%02x\n", eth.src_mac[0], eth.src_mac[1] ,eth.src_mac[2], eth.src_mac[3], eth.src_mac[4], eth.src_mac[5]);
		
		printf("src_ip --> %u.%u.%u.%u\n", (ip.src_ip & 0xFF000000) >> 24, (ip.src_ip & 0x00FF0000) >> 16, (ip.src_ip & 0x0000FF00) >> 8, (ip.src_ip & 0x000000FF));

		printf("dst_ip --> %u.%u.%u.%u\n", (ip.dst_ip & 0xFF000000) >> 24, (ip.dst_ip & 0x00FF0000) >> 16, (ip.dst_ip & 0x0000FF00) >> 8, (ip.dst_ip & 0x000000FF));
		
		printf("src_port --> %u\n", tcp.src_port);

		printf("dst_port --> %u\n", tcp.dst_port);
		
		if(tcp.payload_len != 0) {

			uint16_t print_len = (tcp.payload_len <= 20) ? tcp.payload_len : 20;
			printf("payload --> ");
			for(int i=0; i<print_len; i++){
				 printf("%02x|", tcp.payload[i]);}}

		printf("\n\n");
	
	}
	pcap_close(pcap);

}
