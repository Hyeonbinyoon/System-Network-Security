//1m-block.cpp
#include "hb_headers.h"
#include "http_parser.h"
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_set>


static std::unordered_set<std::string> block_hosts;

static void usage(void)
{
    std::cout << "syntax : 1m-block <site list file>\n";
    std::cout << "sample : 1m-block top-1m.txt\n";
}


static bool load_block_hosts(const std::string& path, std::unordered_set<std::string>& sites)
{
    std::ifstream file(path);

    if (!file.is_open())
    {
        std::cerr << "failed to open file: " << path << "\n";
        return false;
    }

    size_t line_count = 0;
    std::string line;

    while (std::getline(file, line)) 
    {
        line_count++;
    }
    sites.reserve(line_count);

    
    file.clear();
    file.seekg(0);

    while (std::getline(file, line))
    {
        sites.insert(line);
    }

    return true;
}


static bool is_blocked_host(const std::string& host, const std::unordered_set<std::string>& sites)
{
    return sites.find(host) != sites.end();
}


static uint32_t get_packet_id(struct nfq_data* tb)
{
    struct nfqnl_msg_packet_hdr* ph = nfq_get_msg_packet_hdr(tb);
    if (ph != NULL) return ntohl(ph->packet_id);

    return 0;
}



static bool is_blocked_http_request(unsigned char* data, int len)
{
    if (data == NULL || len < HB_IPV4_H_SIZE) return false;

    hb_ip_hdr* ip = reinterpret_cast<hb_ip_hdr*>(data);
    if (ip->version() != IP_VERSION_IPv4) return false;
    if (ip->protocol_value() != IP_PROTOCOL_TCP) return false;

    int ip_header_len = ip->header_len();
    if (ip_header_len < HB_IPV4_H_SIZE) return false;
    if (len < ip_header_len + HB_TCP_H_SIZE) return false;
    

    hb_tcp_hdr* tcp = reinterpret_cast<hb_tcp_hdr*>(data + ip_header_len);
    if (tcp->dst_port_value() != 80) return false;

    int tcp_header_len = tcp->header_len();
    if (tcp_header_len < HB_TCP_H_SIZE) return false;
    if (len < ip_header_len + tcp_header_len) return false;


    int http_offset = ip_header_len + tcp_header_len;
    int http_len = len - http_offset;
    if (http_len <= 0) return false;


    std::string payload(reinterpret_cast<char*>(data + http_offset), http_len);
    std::optional<std::string> host = Http_extract_host(payload);
    if (!host) return false;

    auto begin = std::chrono::steady_clock::now();
    bool blocked = is_blocked_host(*host, block_hosts);
    auto end = std::chrono::steady_clock::now();
    auto lookup_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();

    std::cout << "[HTTP] host=" << *host
              << " lookup_time=" << lookup_ns << " ns"
              << " verdict=" << (blocked ? "DROP" : "ACCEPT")
              << "\n";

    return blocked;
}


static int cb(struct nfq_q_handle* qh, struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data)
{
    std::cout << "entering callback\n";

    uint32_t id = get_packet_id(nfa);
    unsigned char* payload = NULL;
    int payload_len = nfq_get_payload(nfa, &payload);

    if (payload_len >= 0 && is_blocked_http_request(payload, payload_len)) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    std::string list_path = argv[1];

    auto load_begin = std::chrono::steady_clock::now();

    if (!load_block_hosts(list_path, block_hosts))
    {
        return -1;
    }

    auto load_end = std::chrono::steady_clock::now();
    auto load_ms = std::chrono::duration_cast<std::chrono::milliseconds>(load_end - load_begin).count();

    std::cout << "loaded hosts: " << block_hosts.size() << "\n";
    std::cout << "load time: " << load_ms << " ms\n";

    struct nfq_handle* h;
    struct nfq_q_handle* qh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    std::cout << "opening library handle\n";
    h = nfq_open();

    if (h == NULL)
    {
        std::cerr << "error during nfq_open()\n";
        return -1;
    }

    std::cout << "unbinding existing nf_queue handler for AF_INET (if any)\n";

    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        std::cerr << "error during nfq_unbind_pf()\n";
        nfq_close(h);
        return -1;
    }

    std::cout << "binding nfnetlink_queue as nf_queue handler for AF_INET\n";

    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        std::cerr << "error during nfq_bind_pf()\n";
        nfq_close(h);
        return -1;
    }

    std::cout << "binding this socket to queue '0'\n";
    qh = nfq_create_queue(h, 0, &cb, NULL);

    if (qh == NULL)
    {
        std::cerr << "error during nfq_create_queue()\n";
        nfq_close(h);
        return -1;
    }

    std::cout << "setting copy_packet mode\n";

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        std::cerr << "can't set packet_copy mode\n";
        nfq_destroy_queue(qh);
        nfq_close(h);
        return -1;
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
    {
        std::cout << "pkt received\n";
        nfq_handle_packet(h, buf, rv);
    }

    std::cout << "unbinding from queue 0\n";
    nfq_destroy_queue(qh);

    std::cout << "closing library handle\n";
    nfq_close(h);

    return 0;
}
