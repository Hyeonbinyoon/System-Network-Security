#include "rst_sender.h"
#include "checksum.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <vector>


// ============================================================
// Internal state
// ============================================================

static int g_raw_socket = -1;


// ============================================================
// Internal helpers
// ============================================================

static const char* reset_reason_string(ResetReason reason)
{
    if(reason == ResetReason::BLOCKED_BY_SNI) return "BLOCKED_BY_SNI";
    if(reason == ResetReason::BROKEN_FLOW) return "BROKEN_FLOW";

    return "UNKNOWN";
}


static bool send_rst_packet(uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port,
                            uint32_t seq, bool use_ack, uint32_t ack)
{
    if(g_raw_socket < 0)
    {
        ERROR_LOG("raw socket is not initialized");
        return false;
    }

    std::vector<uint8_t> packet(HB_IPV4_H_SIZE + HB_TCP_H_SIZE);
    memset(packet.data(), 0, packet.size());

    hb_ip_hdr* ip = reinterpret_cast<hb_ip_hdr*>(packet.data());
    hb_tcp_hdr* tcp = reinterpret_cast<hb_tcp_hdr*>(packet.data() + HB_IPV4_H_SIZE);

    ip->ver_and_hdr_len = 0x45;
    ip->tos = 0;
    ip->total_len = htons(HB_IPV4_H_SIZE + HB_TCP_H_SIZE);
    ip->id = 0;
    ip->offset = 0;
    ip->ttl = 64;
    ip->protocol = IP_PROTOCOL_TCP;
    ip->src_ip = htonl(src_ip);
    ip->dst_ip = htonl(dst_ip);
    ip->hdr_checksum = ip_checksum(ip);

    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_num = htonl(seq);
    tcp->ack_num = use_ack ? htonl(ack) : 0;
    tcp->hdr_len_and_reserved = (HB_TCP_H_SIZE / 4) << 4;
    tcp->flags = use_ack ? (TCP_FLAG_RST | TCP_FLAG_ACK) : TCP_FLAG_RST;
    tcp->window = 0;
    tcp->checksum = 0;
    tcp->urg_p = 0;
    tcp->checksum = tcp_checksum(ip, tcp, nullptr, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->dst_ip;

    ssize_t sent = sendto(g_raw_socket, packet.data(), packet.size(), 0, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    if(sent < 0)
    {
        perror("sendto");
        return false;
    }

    return true;
}


// ============================================================
// RST sender initialization
// ============================================================

bool set_rst_raw_socket(int raw_socket)
{
    if(raw_socket < 0)
    {
        ERROR_LOG("invalid raw socket");
        return false;
    }

    g_raw_socket = raw_socket;
    return true;
}


// ============================================================
// Flow termination with RST
// ============================================================

void terminate_flow_with_rst(const Flow_Key& key, ResetReason reason)
{
    Flow_Entry flow_copy;

    {
        std::lock_guard<std::mutex> lock(flow_table_mutex);

        auto it = flow_table.find(key);
        if(it == flow_table.end()) return;

        flow_copy = it->second;
        flow_table.erase(it);
    }

    send_bidirectional_rst(flow_copy, reason);

    INFO_LOG("flow terminated with RST: %s", reset_reason_string(reason));
}


// ============================================================
// RST send functions
// ============================================================

bool send_bidirectional_rst(const Flow_Entry& flow, ResetReason reason)
{
    (void)reason;

    bool forward_sent = send_forward_rst(flow);
    bool backward_sent = send_backward_rst(flow);

    if(!forward_sent && !backward_sent)
    {
        ERROR_LOG("failed to send both forward and backward RST");
        return false;
    }

    if(!forward_sent)
        ERROR_LOG("failed to send forward RST");

    if(!backward_sent)
        ERROR_LOG("failed to send backward RST");

    return true;
}


bool send_forward_rst(const Flow_Entry& flow)
{
    bool use_ack = flow.have_last_c2s_ack;
    uint32_t ack = flow.have_last_c2s_ack ? flow.last_c2s_ack : 0;

    return send_rst_packet(flow.client_ip, flow.client_port,
                           flow.server_ip, flow.server_port,
                           flow.c2s_expected_seq,
                           use_ack, ack);
}


bool send_backward_rst(const Flow_Entry& flow)
{
    uint32_t seq = 0;

    if(flow.have_last_c2s_ack)
        seq = flow.last_c2s_ack;

    else if(flow.have_s2c_next_seq)
        seq = flow.s2c_next_seq;

    else
    {
        DEBUG_LOG("backward RST: no valid server-side seq candidate");
        return false;
    }

    return send_rst_packet(flow.server_ip, flow.server_port,
                           flow.client_ip, flow.client_port,
                           seq,
                           true, flow.c2s_expected_seq);
}