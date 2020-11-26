#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "exit.h"

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *customdata) {
    struct nfqnl_msg_packet_hdr *ph;
    struct iphdr *iph;
    uint32_t id;
    int r;
    unsigned char *payload;

    ph = nfq_get_msg_packet_hdr(nfa);
    if(ph){
        id = ntohl(ph->packet_id);
        r = nfq_get_payload(nfa, &payload);
        if(r>=sizeof(*iph)){
            iph = (struct iphdr *)payload;
        }
    }
    return 0;
}


int main(void) {

    struct nfq_handle *h;
    int fd;
    ssize_t rv;
    char buf[4096];


    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    struct nfq_q_handle *qh = nfq_create_queue(h, 10010, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    
    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }


    exitnfq(h);

    return 0;
}