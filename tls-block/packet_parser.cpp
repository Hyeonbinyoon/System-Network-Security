#include "packet_parser.h"


// ============================================================
// Packet parsing
// ============================================================

bool parse_packet_headers(const uint8_t* packet, size_t packet_len,
                          const hb_eth_hdr** eth_hdr,
                          const hb_ip_hdr** ip_hdr,
                          const hb_tcp_hdr** tcp_hdr,
                          const uint8_t** tcp_payload,
                          size_t* tcp_payload_len)
{
    if(packet == nullptr || eth_hdr == nullptr || ip_hdr == nullptr || tcp_hdr == nullptr || tcp_payload == nullptr || tcp_payload_len == nullptr)
        return false;

    *eth_hdr = nullptr;
    *ip_hdr = nullptr;
    *tcp_hdr = nullptr;
    *tcp_payload = nullptr;
    *tcp_payload_len = 0;

    if(packet_len < HB_ETH_H_SIZE) return false;
    const hb_eth_hdr* eth = reinterpret_cast<const hb_eth_hdr*>(packet);
    if(eth->ethertype_value() != ETHERTYPE_IPV4) return false;


    size_t ip_offset = HB_ETH_H_SIZE;
    if(packet_len < ip_offset + HB_IPV4_H_SIZE) return false;
    const hb_ip_hdr* ip = reinterpret_cast<const hb_ip_hdr*>(packet + ip_offset);

    if(ip->version() != IP_VERSION_IPv4) return false;
    if(ip->protocol_value() != IP_PROTOCOL_TCP) return false;

    uint8_t ip_header_len = ip->header_len();
    if(ip_header_len < HB_IPV4_H_SIZE) return false;

    uint16_t ip_total_len = ip->total_length();
    if(ip_total_len < ip_header_len) return false;
    if(packet_len < ip_offset + ip_total_len) return false;

    uint16_t ip_frag_info = ip->offset_value();
    if((ip_frag_info & IP_FLAG_MF) != 0) return false;
    if((ip_frag_info & IP_FRAG_OFFSET_MASK) != 0) return false;


    size_t tcp_offset = ip_offset + ip_header_len;
    if(packet_len < tcp_offset + HB_TCP_H_SIZE) return false;
    const hb_tcp_hdr* tcp = reinterpret_cast<const hb_tcp_hdr*>(packet + tcp_offset);

    uint8_t tcp_header_len = tcp->header_len();
    if(tcp_header_len < HB_TCP_H_SIZE) return false;
    if(ip_total_len < ip_header_len + tcp_header_len) return false;

    size_t payload_offset = tcp_offset + tcp_header_len;
    size_t payload_len = ip_total_len - ip_header_len - tcp_header_len;

    if(packet_len < payload_offset + payload_len) return false;

    *eth_hdr = eth;
    *ip_hdr = ip;
    *tcp_hdr = tcp;
    *tcp_payload = packet + payload_offset;
    *tcp_payload_len = payload_len;

    return true;
}


// ============================================================
// Direction check
// ============================================================

bool is_client_to_server(const Flow_Entry& flow, const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr)
{
    if(ip_hdr == nullptr || tcp_hdr == nullptr) return false;

    return ip_hdr->src_ip_value() == flow.client_ip &&
           tcp_hdr->src_port_value() == flow.client_port &&
           ip_hdr->dst_ip_value() == flow.server_ip &&
           tcp_hdr->dst_port_value() == flow.server_port;
}


bool is_server_to_client(const Flow_Entry& flow, const hb_ip_hdr* ip_hdr, const hb_tcp_hdr* tcp_hdr)
{
    if(ip_hdr == nullptr || tcp_hdr == nullptr) return false;

    return ip_hdr->src_ip_value() == flow.server_ip &&
           tcp_hdr->src_port_value() == flow.server_port &&
           ip_hdr->dst_ip_value() == flow.client_ip &&
           tcp_hdr->dst_port_value() == flow.client_port;
}