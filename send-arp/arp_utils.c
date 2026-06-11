#include "arp_utils.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>



void usage(void) {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp-test wlx90de80099a56 172.20.10.5 172.20.10.1\n");
}



bool get_my_mac(const char* ifname, hb_mac* mac) {
    int fd;
    struct ifreq ifr;

    if (ifname == NULL || mac == NULL) {
        return false;
    }

    *mac = Mac_null();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }

    memcpy(mac->bytes, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);

    close(fd);
    return true;
}



bool get_my_ip(const char* ifname, uint32_t* ip) {
    int fd;
    struct ifreq ifr;

    if (ifname == NULL || ip == NULL) {
        return false;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return false;
    }

    struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
    *ip = ntohl(sin->sin_addr.s_addr);   // host byte order

    close(fd);
    return true;
}



bool get_ip_from_string(const char* ip_str, uint32_t* ip) {
    if (ip_str == NULL || ip == NULL) {
        return false;
    }

    if (!Ip_is_valid_string(ip_str)) {
	usage();    
        return false;
    }

    *ip = Ip_parse(ip_str);   // host byte order
    return true;
}



bool get_other_mac(pcap_t* pcap,
                   hb_mac my_mac,
                   uint32_t my_ip,
                   uint32_t other_ip,
                   hb_mac* other_mac) {
    struct EthArpPacket packet;
    struct pcap_pkthdr* header;
    const u_char* recv_packet;

    if (pcap == NULL || other_mac == NULL) {
        return false;
    }

    *other_mac = Mac_null();
    memset(&packet, 0, sizeof(packet));

    packet.eth.dst_mac = Mac_broadcast();
    packet.eth.src_mac = my_mac;
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hardware_type = htons(ARP_HARDWARE_ETHERNET);
    packet.arp.protocol_type = htons(ETHERTYPE_IPV4);
    packet.arp.hardware_addr_len = MAC_ADDR_LEN;
    packet.arp.protocol_addr_len = ARP_PROTOCOL_ADDR_LEN_IP;
    packet.arp.opcode = htons(ARP_OPCODE_REQUEST);

    packet.arp.sender_mac = my_mac;
    packet.arp.sender_ip = htonl(my_ip);      // host byte order
    packet.arp.target_mac = Mac_null();
    packet.arp.target_ip = htonl(other_ip);   // host byte order

    for(int i = 0; i < 3; i++){
        	int res = pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));
    if(res != 0){
    	fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
        return false;}
    } // request 한번 보내면 reply 못받는 경우 있어서 3번 보냈습니다.


	while (true) {
		int res = pcap_next_ex(pcap, &header, &recv_packet);

		if (res == 0) {
			break;
		}

		if (res == -1 || res == -2) {
			return false;
		}

		if (header->caplen < sizeof(struct EthArpPacket)) {
			continue;
		}

		const struct EthArpPacket* reply = (const struct EthArpPacket*)recv_packet;

		if (ntohs(reply->eth.ethertype) != ETHERTYPE_ARP) {
			continue;
		}

		if (ntohs(reply->arp.opcode) != ARP_OPCODE_REPLY) {
			continue;
		}

		if (ntohl(reply->arp.sender_ip) != other_ip) {
			continue;
		}

		if (ntohl(reply->arp.target_ip) != my_ip) {
			continue;
		}

		if (memcmp(reply->eth.dst_mac.bytes, my_mac.bytes, MAC_ADDR_LEN) != 0) {
			continue;
		}

		if (memcmp(reply->arp.target_mac.bytes, my_mac.bytes, MAC_ADDR_LEN) != 0) {
			continue;
		}

		*other_mac = reply->arp.sender_mac;
		return true;
	}
    
    

    return false;
}
