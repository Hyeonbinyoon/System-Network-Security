// checksum.cpp
#include "checksum.h"

#include <arpa/inet.h>
#include <string.h>
#include <vector>


#pragma pack(push, 1)
struct TcpPseudoHeader
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};
#pragma pack(pop)


static uint16_t check_sum(uint16_t* ptr, int len)
{
    uint32_t sum = 0;
    uint16_t odd = 0;

    while (len > 1){ sum += *ptr++;  len -= 2;}

    if (len == 1) { *(uint8_t*)(&odd) = *(uint8_t*)ptr;  sum += odd;}

    while (sum >> 16) {sum = (sum >> 16) + (sum & 0xffff);}

    return ~sum;
}


uint16_t ip_checksum(hb_ip_hdr* ip)
{
    ip->hdr_checksum = 0;
    return check_sum(reinterpret_cast<uint16_t*>(ip), ip->header_len());
}


uint16_t tcp_checksum(const hb_ip_hdr* ip, const hb_tcp_hdr* tcp, const uint8_t* data, uint32_t data_len)
{
    uint8_t tcp_header_len = tcp->header_len();
    uint16_t tcp_len = tcp_header_len + data_len;

    TcpPseudoHeader pseudo;
    pseudo.src_ip = ip->src_ip;
    pseudo.dst_ip = ip->dst_ip;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.tcp_len = htons(tcp_len);

    std::vector<uint8_t> buf(sizeof(TcpPseudoHeader) + tcp_len);

    memcpy(buf.data(), &pseudo, sizeof(TcpPseudoHeader));
    memcpy(buf.data() + sizeof(TcpPseudoHeader), tcp, tcp_header_len);

    if (data_len > 0) memcpy(buf.data() + sizeof(TcpPseudoHeader) + tcp_header_len, data, data_len);

    return check_sum(reinterpret_cast<uint16_t*>(buf.data()), (int)buf.size());
}