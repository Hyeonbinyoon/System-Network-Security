//arp_utils.c
#include "arp_utils.h"
#include <stdlib.h>
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

    if (ifname == NULL || mac == NULL) return false;

    *mac = Mac_null();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

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

    if (ifname == NULL || ip == NULL) return false;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

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



bool get_other_mac(pcap_t* pcap, hb_mac my_mac, uint32_t my_ip, hb_mac* other_mac, uint32_t other_ip) {
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
        
		if (res == 0) break;
		if (res == -1 || res == -2) return false;
		if (header->caplen < sizeof(struct EthArpPacket)) continue;

		const struct EthArpPacket* reply = (const struct EthArpPacket*)recv_packet;
		if (ntohs(reply->eth.ethertype) != ETHERTYPE_ARP) continue;
		if (ntohs(reply->arp.opcode) != ARP_OPCODE_REPLY) continue;
		if (ntohl(reply->arp.sender_ip) != other_ip) continue;
		if (ntohl(reply->arp.target_ip) != my_ip) continue;
		if (memcmp(reply->eth.dst_mac.bytes, my_mac.bytes, MAC_ADDR_LEN) != 0) continue;
		if (memcmp(reply->arp.target_mac.bytes, my_mac.bytes, MAC_ADDR_LEN) != 0) continue;

		*other_mac = reply->arp.sender_mac;
		return true;
	}
    
    

    return false;
}


bool send_arp_reply(pcap_t* pcap, hb_mac sender_mac, uint32_t sender_ip, hb_mac target_mac, uint32_t target_ip) {
    struct EthArpPacket packet;

    if (pcap == NULL) {
        return false;
    }

    memset(&packet, 0, sizeof(packet));

    packet.eth.dst_mac = target_mac;
    packet.eth.src_mac = sender_mac;
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hardware_type = htons(ARP_HARDWARE_ETHERNET);
    packet.arp.protocol_type = htons(ETHERTYPE_IPV4);
    packet.arp.hardware_addr_len = MAC_ADDR_LEN;
    packet.arp.protocol_addr_len = ARP_PROTOCOL_ADDR_LEN_IP;
    packet.arp.opcode = htons(ARP_OPCODE_REPLY);

    packet.arp.sender_mac = sender_mac;
    packet.arp.sender_ip = htonl(sender_ip);
    packet.arp.target_mac = target_mac;
    packet.arp.target_ip = htonl(target_ip);

    for (int i = 0; i < 3; i++) {
        int res = pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n",
                    res, pcap_geterr(pcap));
            return false;
        }
    }

    return true;
}


bool send_arp_infect_reply(pcap_t* pcap, hb_mac sender_mac, uint32_t sender_ip, hb_mac my_mac, uint32_t target_ip) {
    struct EthArpPacket packet;

    if (pcap == NULL) {
        return false;
    }

    memset(&packet, 0, sizeof(packet));

    packet.eth.dst_mac = sender_mac;
    packet.eth.src_mac = my_mac;
    packet.eth.ethertype = htons(ETHERTYPE_ARP);

    packet.arp.hardware_type = htons(ARP_HARDWARE_ETHERNET);
    packet.arp.protocol_type = htons(ETHERTYPE_IPV4);
    packet.arp.hardware_addr_len = MAC_ADDR_LEN;
    packet.arp.protocol_addr_len = ARP_PROTOCOL_ADDR_LEN_IP;
    packet.arp.opcode = htons(ARP_OPCODE_REPLY);

    packet.arp.sender_mac = my_mac;
    packet.arp.sender_ip = htonl(target_ip);
    packet.arp.target_mac = sender_mac;
    packet.arp.target_ip = htonl(sender_ip);

    
    int res = pcap_sendpacket(pcap, (const u_char*)&packet, sizeof(packet));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n",
                res, pcap_geterr(pcap));
        return false;
    }
    
    return true;
}   //코드의 의미를 높이기 위해 만들었습니다.


Flow* create_flow(uint32_t sender_ip, hb_mac sender_mac, uint32_t target_ip, hb_mac target_mac) {
    Flow* node = (Flow*)malloc(sizeof(Flow));
    if (node == NULL) {
        return NULL;    // malloc실패시
    }

    node->sender_ip = sender_ip;    // flow들의 ip주소는 host byte로 처리
    node->sender_mac = sender_mac;
    node->target_ip = target_ip;
    node->target_mac = target_mac;  
    node->next = NULL;

    return node;
}


bool append_flow(Flow** head, Flow* node) {
    if (head == NULL || node == NULL) return false;    // head 포인터가 잘못 들어오거나, 이어서 붙일 노드가 없을 시

    if (*head == NULL) {
        *head = node;    // 리스트의 시작
        return true;
    }

    Flow* cur = *head;
    while (cur->next != NULL) {
        cur = cur->next; // 맨 끝의 노드로 이동
    }

    cur->next = node;    // 노드 이어붙이기
    return true;
}

void free_flow_list(Flow* head) {
    while (head != NULL) {
        Flow* next = head->next;
        free(head);
        head = next;
    }
}       // 리스트 생성할 때 할당받은 메모리 해제 함수



// helper함수들
static bool Mac_equal(hb_mac a, hb_mac b) {
    return memcmp(a.bytes, b.bytes, MAC_ADDR_LEN) == 0;
}

static bool Ip_equal(uint32_t a, uint32_t b) {
    return (a == b);
}

static bool is_basic_arp_request(const struct EthArpPacket* packet) {

    if (packet == NULL) return false;
    if (ntohs(packet->eth.ethertype) != ETHERTYPE_ARP) return false;
    if (ntohs(packet->arp.hardware_type) != ARP_HARDWARE_ETHERNET) return false;
    if (ntohs(packet->arp.protocol_type) != ETHERTYPE_IPV4) return false;
    if (packet->arp.hardware_addr_len != MAC_ADDR_LEN) return false;
    if (packet->arp.protocol_addr_len != ARP_PROTOCOL_ADDR_LEN_IP) return false;
    if (ntohs(packet->arp.opcode) != ARP_OPCODE_REQUEST) return false;

    return true;
}



// recover packet checking 함수들
bool check_sender_broadcast_arp_request(const struct EthArpPacket* packet, const Flow* flow) {
    if (packet == NULL || flow == NULL) return false;
    if (!is_basic_arp_request(packet)) return false;
    if (!Mac_is_broadcast(packet->eth.dst_mac)) return false;
    if (!Mac_equal(packet->eth.src_mac, flow->sender_mac)) return false;
    if (!Mac_equal(packet->arp.sender_mac, flow->sender_mac)) return false;
    if (!Ip_equal(ntohl(packet->arp.sender_ip), flow->sender_ip)) return false;
    if (!Ip_equal(ntohl(packet->arp.target_ip), flow->target_ip)) return false;
    if (!Mac_is_null(packet->arp.target_mac)) return false;

    return true;
}


bool check_sender_unicast_arp_request_to_me(const struct EthArpPacket* packet, const Flow* flow, hb_mac my_mac) {
    if (packet == NULL || flow == NULL) return false;
    if (!is_basic_arp_request(packet)) return false;
    if (!Mac_equal(packet->eth.dst_mac, my_mac)) return false;
    if (!Mac_equal(packet->eth.src_mac, flow->sender_mac)) return false;
    if (!Mac_equal(packet->arp.sender_mac, flow->sender_mac)) return false;
    if (!Ip_equal(ntohl(packet->arp.sender_ip), flow->sender_ip)) return false;
    if (!Ip_equal(ntohl(packet->arp.target_ip) , flow->target_ip)) return false;
    if (!Mac_is_null(packet->arp.target_mac) && !Mac_equal(packet->arp.target_mac, my_mac)) return false;
    return true;
}

bool check_target_broadcast_arp_request(const struct EthArpPacket* packet, const Flow* flow) {
    if (packet == NULL || flow == NULL) return false;
    if (!is_basic_arp_request(packet)) return false;
    if (!Mac_is_broadcast(packet->eth.dst_mac)) return false;
    if (!Mac_equal(packet->eth.src_mac, flow->target_mac)) return false;
    if (!Mac_equal(packet->arp.sender_mac, flow->target_mac)) return false;
    if (!Ip_equal((packet->arp.sender_ip), flow->target_ip)) return false;
    if (!Ip_equal(ntohl(packet->arp.target_ip), flow->sender_ip)) return false;
    if (!Mac_is_null(packet->arp.target_mac)) return false;

    return true;
}


Flow* find_flow_from_arp_request(Flow* head, const struct EthArpPacket* packet, hb_mac my_mac, FlowPacketType* type) {
    Flow* cur = head;

    if (type != NULL) *type = FLOW_PACKET_NONE;

    while (cur != NULL) {
        if (check_sender_broadcast_arp_request(packet, cur)) {
            if (type != NULL) *type = FLOW_PACKET_SENDER_BROADCAST_REQ;
            return cur;
        }

        if (check_sender_unicast_arp_request_to_me(packet, cur, my_mac)) {
            if (type != NULL) *type = FLOW_PACKET_SENDER_UNICAST_REQ_TO_ME;
            return cur;
        }

        if (check_target_broadcast_arp_request(packet, cur)) {
            if (type != NULL) *type = FLOW_PACKET_TARGET_BROADCAST_REQ;
            return cur;
        }

        cur = cur->next;
    }

    return NULL;
}

bool check_ip_packet(const struct EthArpPacket* packet, const Flow* flow) {
    if (packet == NULL || flow == NULL) return false;
    if (!is_basic_arp_request(packet)) return false;
    if (!Mac_is_broadcast(packet->eth.dst_mac)) return false;
    if (!Mac_equal(packet->eth.src_mac, flow->sender_mac)) return false;
    if (!Mac_equal(packet->arp.sender_mac, flow->sender_mac)) return false;
    if (ntohl(packet->arp.sender_ip) != flow->sender_ip) return false;
    if (ntohl(packet->arp.target_ip) != flow->target_ip) return false;
    if (!Mac_is_null(packet->arp.target_mac)) return false;

    return true;
}


Flow* find_flow_from_ip_packet(Flow* head, const struct EthIpPacket* packet, uint32_t my_ip) {

    if (packet == NULL) return NULL;
    if ((packet->ip.ver_and_hdr_len >> 4) != IP_VERSION_IPv4) return NULL;
    Flow* cur = head;

    while (cur != NULL) {
        int c1 = Mac_equal(packet->eth.src_mac, cur->sender_mac);
        int c4 = Ip_equal(ntohl(packet->ip.dst_ip), my_ip);


        if (!c1) { cur = cur->next; continue; }
        if (c4)  { cur = cur->next; continue; }
        return cur;

    }
    
    return NULL;
}

