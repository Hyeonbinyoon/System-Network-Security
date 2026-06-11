#include "packet.h"
#include "http_parser.h"
#include "checksum.h"

#include <algorithm>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <optional>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>


static const uint8_t TCP_RST = 0x04;
static const uint8_t TCP_ACK = 0x10;
static const uint8_t TCP_FIN = 0x01;

static const char REDIRECT_MSG[] =
    "HTTP/1.0 302 Redirect\r\n"
    "Location: http://warning.or.kr\r\n"
    "\r\n";


bool get_interface_mac(const char* interface, hb_mac* mac)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl(SIOCGIFHWADDR)");
        close(sock);
        return false;
    }

    memcpy(mac->bytes, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);

    close(sock);
    return true;
}


bool parse_packet(const struct pcap_pkthdr* header, const uint8_t* packet, ParsedPacket* parsed)
{
    if (header->caplen < HB_ETH_H_SIZE + HB_IPV4_H_SIZE) return false;

    memset(parsed, 0, sizeof(ParsedPacket));

    parsed->eth = reinterpret_cast<const hb_eth_hdr*>(packet);
    if (parsed->eth->ethertype_value() != ETHERTYPE_IPV4) return false;

    parsed->ip = reinterpret_cast<const hb_ip_hdr*>(packet + HB_ETH_H_SIZE);
    if (parsed->ip->version() != IP_VERSION_IPv4) return false;
    if (parsed->ip->protocol_value() != IP_PROTOCOL_TCP) return false;

    uint8_t ip_header_len = parsed->ip->header_len();
    if (ip_header_len < HB_IPV4_H_SIZE) return false;

    uint16_t ip_total_len = parsed->ip->total_length();
    if (ip_total_len < ip_header_len + HB_TCP_H_SIZE)return false;

    if (header->caplen < HB_ETH_H_SIZE + ip_total_len)return false;

    uint16_t frag = parsed->ip->offset_value();
    if ((frag & (IP_FLAG_MF | IP_FRAG_OFFSET_MASK)) != 0) return false;

    parsed->tcp = reinterpret_cast<const hb_tcp_hdr*>(packet + HB_ETH_H_SIZE + ip_header_len);
    uint8_t tcp_header_len = parsed->tcp->header_len();

    if (tcp_header_len < HB_TCP_H_SIZE) return false;
    if (ip_total_len < ip_header_len + tcp_header_len) return false;

    parsed->tcp_data = packet + HB_ETH_H_SIZE + ip_header_len + tcp_header_len;
    parsed->tcp_data_size = ip_total_len - ip_header_len - tcp_header_len;

    return true;
}


static bool starts_with(const std::string& s, const char* prefix)
{
    return s.rfind(prefix, 0) == 0;
}


bool contains_pattern(const ParsedPacket& parsed, const std::string& pattern)
{
    if (pattern.empty()) return false;
    if (parsed.tcp_data_size == 0) return false;

    std::string payload(reinterpret_cast<const char*>(parsed.tcp_data), parsed.tcp_data_size);

    if (starts_with(pattern, "Host: "))
    {
        std::optional<std::string> host = Http_extract_host(payload);
        if (!host.has_value()) return false;

        std::string target_host = pattern.substr(6);
        return host.value() == target_host;
    }

    const uint8_t* begin = parsed.tcp_data;
    const uint8_t* end = parsed.tcp_data + parsed.tcp_data_size;

    auto it = std::search(begin, end, pattern.begin(), pattern.end());

    return it != end;
}


bool send_forward_rst(pcap_t* pcap_handle, const hb_mac& my_mac, const ParsedPacket& org)
{
    std::vector<uint8_t> packet(HB_ETH_H_SIZE + HB_IPV4_H_SIZE + HB_TCP_H_SIZE);

    memset(packet.data(), 0, packet.size());

    hb_eth_hdr* eth = reinterpret_cast<hb_eth_hdr*>(packet.data());
    hb_ip_hdr* ip = reinterpret_cast<hb_ip_hdr*>(packet.data() + HB_ETH_H_SIZE);
    hb_tcp_hdr* tcp = reinterpret_cast<hb_tcp_hdr*>(packet.data() + HB_ETH_H_SIZE + HB_IPV4_H_SIZE);

    memcpy(eth->dst_mac.bytes, org.eth->dst_mac.bytes, MAC_ADDR_LEN);
    memcpy(eth->src_mac.bytes, my_mac.bytes, MAC_ADDR_LEN);
    eth->ethertype = htons(ETHERTYPE_IPV4);

    ip->ver_and_hdr_len = 0x45;
    ip->tos = org.ip->tos;
    ip->total_len = htons(HB_IPV4_H_SIZE + HB_TCP_H_SIZE);
    ip->id = org.ip->id;
    ip->offset = 0;
    ip->ttl = org.ip->ttl;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->src_ip = org.ip->src_ip;
    ip->dst_ip = org.ip->dst_ip;
    ip->hdr_checksum = ip_checksum(ip);

    tcp->src_port = org.tcp->src_port;
    tcp->dst_port = org.tcp->dst_port;
    tcp->seq_num = htonl(ntohl(org.tcp->seq_num) + org.tcp_data_size);
    tcp->ack_num = org.tcp->ack_num;
    tcp->hdr_len_and_reserved = (HB_TCP_H_SIZE / 4) << 4;
    tcp->flags = TCP_RST | TCP_ACK;
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urg_p = 0;
    tcp->checksum = tcp_checksum(ip, tcp, nullptr, 0);

    if (pcap_sendpacket(pcap_handle, packet.data(), packet.size()) != 0)
    {
        fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(pcap_handle));
        return false;
    }

    return true;
}


bool send_backward_fin(int raw_socket, const ParsedPacket& org)
{
    const uint8_t* redirect_data = reinterpret_cast<const uint8_t*>(REDIRECT_MSG);
    uint32_t redirect_len = strlen(REDIRECT_MSG);

    std::vector<uint8_t> packet(HB_IPV4_H_SIZE + HB_TCP_H_SIZE + redirect_len);

    memset(packet.data(), 0, packet.size());

    hb_ip_hdr* ip = reinterpret_cast<hb_ip_hdr*>(packet.data());
    hb_tcp_hdr* tcp = reinterpret_cast<hb_tcp_hdr*>(packet.data() + HB_IPV4_H_SIZE);
    uint8_t* data = packet.data() + HB_IPV4_H_SIZE + HB_TCP_H_SIZE;

    memcpy(data, redirect_data, redirect_len);

    ip->ver_and_hdr_len = 0x45;
    ip->tos = org.ip->tos;
    ip->total_len = htons(HB_IPV4_H_SIZE + HB_TCP_H_SIZE + redirect_len);
    ip->id = org.ip->id;
    ip->offset = 0;
    ip->ttl = 128;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->src_ip = org.ip->dst_ip;
    ip->dst_ip = org.ip->src_ip;
    ip->hdr_checksum = ip_checksum(ip);

    tcp->src_port = org.tcp->dst_port;
    tcp->dst_port = org.tcp->src_port;
    tcp->seq_num = org.tcp->ack_num;
    tcp->ack_num = htonl(ntohl(org.tcp->seq_num) + org.tcp_data_size);
    tcp->hdr_len_and_reserved = (HB_TCP_H_SIZE / 4) << 4;
    tcp->flags = TCP_FIN | TCP_ACK;
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urg_p = 0;
    tcp->checksum = tcp_checksum(ip, tcp, data, redirect_len);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dst_ip;

    ssize_t sent = sendto(raw_socket, packet.data(), packet.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    if (sent < 0)
    {
        perror("sendto");
        return false;
    }

    return true;
}