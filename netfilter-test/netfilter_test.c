#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "hb_headers.h"


void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}
//dump함수는 프로그램 짜면서 디버깅할 때만 이용하였고, 최종 코드에서는 너무 산만하여 이용하지 않았습니다.


static void usage(void)
{
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test korea.ac.kr\n");
}


static const char *block_host = NULL;


static u_int32_t get_packet_id(struct nfq_data *nfa)
{
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph == NULL) return 0;

    return ntohl(ph->packet_id);
}



static bool is_blocked_get_request(unsigned char *data, int len)
{
    if (len < HB_IPV4_H_SIZE) return false;

    hb_ip_hdr *ip = (hb_ip_hdr *)data;
    int ip_hdr_len = (ip->ver_and_hdr_len & 0x0F) * 4;

    if (ip->protocol != IP_PROTOCOL_TCP) return false;
    if (len < ip_hdr_len + HB_TCP_H_SIZE) return false;


    hb_tcp_hdr *tcp = (hb_tcp_hdr *)(data + ip_hdr_len);

    if (ntohs(tcp->dst_port) != 80) return false;
    int tcp_hdr_len = ((tcp->hdr_len_and_reserved >> 4) & 0x0F) * 4;
    if (len < ip_hdr_len + tcp_hdr_len) return false;

    
    unsigned char *http = data + ip_hdr_len + tcp_hdr_len;
    int http_len = len - ip_hdr_len - tcp_hdr_len;

    

    if (memcmp(http, "GET ", 4) != 0) return false;
    char *http_str = (char*)malloc(http_len + 1);
    if (http_str == NULL) return false;
    memcpy(http_str, http, http_len);
    http_str[http_len] = '\0';

   
    char *host = strstr(http_str, "Host: ");
    if (host == NULL) {
        free(http_str);
        return false;
    }
    host += strlen("Host: ");

    char * host_end = strstr(host, "\r\n");
    if (host_end != NULL) *host_end = '\0';

    
    bool result = (strcmp(host, block_host) == 0);

    free(http_str);
    return result;
}



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = get_packet_id(nfa);
	printf("entering callback\n");

    unsigned char *payload;
    int payload_len;
    int verdict = NF_ACCEPT;

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= 0) {
        if (is_blocked_get_request(payload, payload_len)) {
            printf("blocked host: %s\n", block_host);
            verdict = NF_DROP;
        }
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}




int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;

    int fd;
    int rv;

    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        usage();
        return 1;
    }

    block_host = argv[1];

    printf("opening library handle\n");
    h = nfq_open();
    if (h == NULL) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        nfq_close(h);
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        nfq_close(h);
        exit(1);
    }

    printf("binding this socket to queue 0\n");
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (qh == NULL) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        nfq_close(h);
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        exit(1);
    }

    fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    return 0;
}


