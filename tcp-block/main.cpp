#include "packet.h"

#include <pcap.h>
#include <stdio.h>
#include <string>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage()
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block ens33 \"Host: youtube.com\"\n");
}

static void print_mac(const hb_mac& mac)
{
    printf(
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac.bytes[0],
        mac.bytes[1],
        mac.bytes[2],
        mac.bytes[3],
        mac.bytes[4],
        mac.bytes[5]
    );
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }

    std::string interface = argv[1];
    std::string pattern = argv[2];

    hb_mac my_mac;
    if (!get_interface_mac(interface.c_str(), &my_mac)) return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1, errbuf);

    if (pcap_handle == nullptr)
    {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return -1;
    }

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (raw_socket < 0)
    {
        perror("socket");
        pcap_close(pcap_handle);
        return -1;
    }

    int opt = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt");
        close(raw_socket);
        pcap_close(pcap_handle);
        return -1;
    }



    printf("tcp-block started\n");
    printf("interface : %s\n", interface.c_str());
    printf("my mac    : ");
    print_mac(my_mac);
    printf("\n");
    printf("pattern   : %s\n", pattern.c_str());



    while (true)
    {
        struct pcap_pkthdr* header;
        const uint8_t* packet;

        int res = pcap_next_ex(pcap_handle, &header, &packet);
        if (res == 0)continue;
        if (res == PCAP_ERROR_BREAK) break;

        if (res == PCAP_ERROR)
        {
            fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(pcap_handle));
            break;
        }

        ParsedPacket parsed;

        if (!parse_packet(header, packet, &parsed)) continue;
        if (!contains_pattern(parsed, pattern)) continue;

        printf("pattern detected\n");

        printf("before forward\n");
        if (send_forward_rst(pcap_handle, my_mac, parsed))
            printf("forward rst sent\n");
        else
            printf("forward rst failed\n");

        printf("before backward\n");
        if (send_backward_fin(raw_socket, parsed))
            printf("backward fin sent\n");
        else
            printf("backward fin failed\n");

        printf("after backward\n");

    }

    close(raw_socket);
    pcap_close(pcap_handle);

    return 0;
}