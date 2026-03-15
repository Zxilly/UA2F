/*
 * musl compatibility compile check.
 *
 * Compiled with musl-gcc in CI to verify that production code's struct
 * field accesses are portable across glibc and musl.
 *
 * This file mirrors the exact field access patterns used in src/handler.c
 * and other production sources. If handler.c starts using a glibc-specific
 * field name, the corresponding pattern must be added here — and musl-gcc
 * will catch the incompatibility at compile time.
 *
 * Build:
 *   musl-gcc -fsyntax-only -std=gnu17 test/musl_compat_check.c
 */

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <string.h>

/*
 * Mirrors handler.c session key extraction:
 *   tuple.src_port = ntohs(tcp_hdr->th_sport);
 *   tuple.dst_port = ntohs(tcp_hdr->th_dport);
 */
static void check_tcphdr_port_access(const struct tcphdr *tcp_hdr) {
    (void)ntohs(tcp_hdr->th_sport);
    (void)ntohs(tcp_hdr->th_dport);
}

/*
 * Mirrors packet_builder.cc TCP header construction:
 *   tcp->th_sport = htons(src_port);
 *   tcp->th_dport = htons(dst_port);
 *   tcp->th_off   = tcp_hdr_len / 4;
 *   tcp->th_flags = TH_ACK;
 *   tcp->th_win   = htons(65535);
 */
static void check_tcphdr_construction(struct tcphdr *tcp) {
    tcp->th_sport = htons(12345);
    tcp->th_dport = htons(80);
    tcp->th_off = 5;
    tcp->th_flags = TH_ACK;
    tcp->th_win = htons(65535);
    tcp->th_seq = htonl(1000);
    tcp->th_ack = htonl(2000);
    tcp->th_sum = 0;
    tcp->th_urp = 0;
}

/*
 * Mirrors handler.c IP header access for session key extraction.
 */
static void check_iphdr_access(const struct iphdr *ip) {
    (void)ip->version;
    (void)ip->ihl;
    (void)ip->tot_len;
    (void)ip->protocol;
    (void)ip->saddr;
    (void)ip->daddr;
    (void)ip->check;
}

static void check_ip6hdr_access(const struct ip6_hdr *ip6) {
    (void)ip6->ip6_src;
    (void)ip6->ip6_dst;
    (void)ip6->ip6_nxt;
    (void)ip6->ip6_plen;
    (void)ip6->ip6_hlim;
}

/* Prevent unused-function warnings */
int main(void) {
    struct tcphdr t;
    struct iphdr ip;
    struct ip6_hdr ip6;
    memset(&t, 0, sizeof(t));
    memset(&ip, 0, sizeof(ip));
    memset(&ip6, 0, sizeof(ip6));
    check_tcphdr_port_access(&t);
    check_tcphdr_construction(&t);
    check_iphdr_access(&ip);
    check_ip6hdr_access(&ip6);
    return 0;
}
