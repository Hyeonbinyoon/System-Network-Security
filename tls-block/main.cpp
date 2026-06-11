#include "common.h"
#include "flow.h"
#include "rst_sender.h"
#include "tls_record_reassembly.h"
#include "tls_handshake_reassembly.h"

#include <pcap.h>

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>


// ============================================================
// Global config
// ============================================================

std::string target_server_name;


// ============================================================
// Internal state
// ============================================================

static std::atomic<bool> stop_requested(false);
static pcap_t* g_pcap_handle = nullptr;


// ============================================================
// Usage
// ============================================================

static void usage(const char* program)
{
    std::fprintf(stderr, "syntax: %s <interface> <server_name>\n", program);
    std::fprintf(stderr, "sample: %s ens33 korea.ac.kr\n", program);
}


// ============================================================
// Signal handling
// ============================================================

static void signal_handler(int signo)
{
    (void)signo;

    stop_requested.store(true);

    if(g_pcap_handle != nullptr)
        pcap_breakloop(g_pcap_handle);

    ready_flow_cv.notify_all();
}


// ============================================================
// pcap callback
// ============================================================

static void pcap_packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    (void)user;

    if(stop_requested.load()) return;
    if(header == nullptr || packet == nullptr) return;

    handle_captured_packet(packet, header->caplen);
}


// ============================================================
// pcap filter
// ============================================================

static bool set_pcap_filter(pcap_t* pcap, const char* filter_exp)
{
    if(pcap == nullptr || filter_exp == nullptr) return false;

    struct bpf_program fp;

    if(pcap_compile(pcap, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        ERROR_LOG("pcap_compile failed: %s", pcap_geterr(pcap));
        return false;
    }

    if(pcap_setfilter(pcap, &fp) < 0)
    {
        ERROR_LOG("pcap_setfilter failed: %s", pcap_geterr(pcap));
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);

    return true;
}


// ============================================================
// raw socket
// ============================================================

static int open_raw_socket()
{
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(raw_socket < 0)
    {
        perror("socket");
        return -1;
    }

    int on = 1;

    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt(IP_HDRINCL)");
        close(raw_socket);
        return -1;
    }

    return raw_socket;
}


// ============================================================
// 1단계 capture worker
// ============================================================

static void capture_worker(pcap_t* pcap)
{
    if(pcap == nullptr) return;

    INFO_LOG("capture worker started");

    int result = pcap_loop(pcap, 0, pcap_packet_handler, nullptr);

    if(result == PCAP_ERROR)
        ERROR_LOG("pcap_loop failed: %s", pcap_geterr(pcap));

    stop_requested.store(true);
    ready_flow_cv.notify_all();

    INFO_LOG("capture worker stopped");
}


// ============================================================
// 2단계 handshake worker
// ============================================================

static void handshake_worker()
{
    INFO_LOG("handshake worker started");

    while(!stop_requested.load())
    {
        bool should_reset = false;
        Flow_Key reset_key;
        ResetReason reset_reason = ResetReason::BROKEN_FLOW;

        {
            std::unique_lock<std::mutex> lock(flow_table_mutex);

            ready_flow_cv.wait(lock, [] {
                return stop_requested.load() || !ready_flow_queue.empty();
            });

            if(stop_requested.load() && ready_flow_queue.empty())
                break;

            if(ready_flow_queue.empty())
                continue;

            Flow_Key key = ready_flow_queue.front();
            ready_flow_queue.pop();

            auto it = flow_table.find(key);
            if(it == flow_table.end())
                continue;

            HandshakeReassemblyResult result = process_ready_flow(key, it->second);

            if(result == HandshakeReassemblyResult::NOT_TARGET)
            {
                remove_flow_without_rst(key);
                continue;
            }

            if(result == HandshakeReassemblyResult::BROKEN_FLOW)
            {
                should_reset = true;
                reset_key = key;
                reset_reason = ResetReason::BROKEN_FLOW;
            }

            if(result == HandshakeReassemblyResult::BLOCKED_BY_SNI)
            {
                should_reset = true;
                reset_key = key;
                reset_reason = ResetReason::BLOCKED_BY_SNI;
            }
        } // mutex unlock

        if(should_reset)
            terminate_flow_with_rst(reset_key, reset_reason);
    }

    INFO_LOG("handshake worker stopped");
}


// ============================================================
// Cleanup worker
// ============================================================

static void cleanup_worker()
{
    INFO_LOG("cleanup worker started");

    while(!stop_requested.load())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        cleanup_expired_flows();
    }

    INFO_LOG("cleanup worker stopped");
}


// ============================================================
// main
// ============================================================

int main(int argc, char* argv[])
{
    char name[] = "홍길동";
    std::printf("[sub26-2026]tls-block[%s]\n", name);

    if(argc != 3)
    {
        usage(argv[0]);
        return -1;
    }

    const char* interface = argv[1];
    target_server_name = argv[2];

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);

    if(pcap == nullptr)
    {
        ERROR_LOG("pcap_open_live failed: %s", errbuf);
        return -1;
    }

    g_pcap_handle = pcap;

    if(!set_pcap_filter(pcap, "tcp"))
    {
        pcap_close(pcap);
        g_pcap_handle = nullptr;
        return -1;
    }

    int raw_socket = open_raw_socket();

    if(raw_socket < 0)
    {
        pcap_close(pcap);
        g_pcap_handle = nullptr;
        return -1;
    }

    if(!set_rst_raw_socket(raw_socket))
    {
        close(raw_socket);
        pcap_close(pcap);
        g_pcap_handle = nullptr;
        return -1;
    }

    INFO_LOG("interface: %s", interface);
    INFO_LOG("target server name: %s", target_server_name.c_str());

    std::thread capture_thread(capture_worker, pcap);
    std::thread handshake_thread(handshake_worker);
    std::thread cleanup_thread(cleanup_worker);

    capture_thread.join();

    stop_requested.store(true);
    ready_flow_cv.notify_all();

    handshake_thread.join();
    cleanup_thread.join();

    close(raw_socket);

    pcap_close(pcap);
    g_pcap_handle = nullptr;

    INFO_LOG("tls-block terminated");

    return 0;
}