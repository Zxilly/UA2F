#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct tcphdr; struct iphdr; struct ip6_hdr; struct pkt_buff;
static unsigned long long tcp4_calls, tcp6_calls, ip4_calls, mangle4_calls, mangle6_calls, sysconf_calls, pagesize_calls;
#define RESOLVE(name) do { if (!real_##name) { *(void **)(&real_##name) = dlsym(RTLD_NEXT, #name); if (!real_##name) _exit(127); } } while (0)
void nfq_tcp_compute_checksum_ipv4(struct tcphdr *tcp, struct iphdr *ip) {
    static void (*real_nfq_tcp_compute_checksum_ipv4)(struct tcphdr *, struct iphdr *);
    RESOLVE(nfq_tcp_compute_checksum_ipv4); ++tcp4_calls; real_nfq_tcp_compute_checksum_ipv4(tcp, ip);
}
void nfq_tcp_compute_checksum_ipv6(struct tcphdr *tcp, struct ip6_hdr *ip) {
    static void (*real_nfq_tcp_compute_checksum_ipv6)(struct tcphdr *, struct ip6_hdr *);
    RESOLVE(nfq_tcp_compute_checksum_ipv6); ++tcp6_calls; real_nfq_tcp_compute_checksum_ipv6(tcp, ip);
}
void nfq_ip_set_checksum(struct iphdr *ip) {
    static void (*real_nfq_ip_set_checksum)(struct iphdr *);
    RESOLVE(nfq_ip_set_checksum); ++ip4_calls; real_nfq_ip_set_checksum(ip);
}
int nfq_tcp_mangle_ipv4(struct pkt_buff *p, unsigned off, unsigned len, const char *r, unsigned n) {
    static int (*real_nfq_tcp_mangle_ipv4)(struct pkt_buff *, unsigned, unsigned, const char *, unsigned);
    RESOLVE(nfq_tcp_mangle_ipv4); ++mangle4_calls; return real_nfq_tcp_mangle_ipv4(p, off, len, r, n);
}
int nfq_tcp_mangle_ipv6(struct pkt_buff *p, unsigned off, unsigned len, const char *r, unsigned n) {
    static int (*real_nfq_tcp_mangle_ipv6)(struct pkt_buff *, unsigned, unsigned, const char *, unsigned);
    RESOLVE(nfq_tcp_mangle_ipv6); ++mangle6_calls; return real_nfq_tcp_mangle_ipv6(p, off, len, r, n);
}
long sysconf(int name) {
    static long (*real_sysconf)(int);
    RESOLVE(sysconf); ++sysconf_calls;
    if (name == _SC_PAGESIZE) ++pagesize_calls;
    return real_sysconf(name);
}
__attribute__((destructor)) static void report(void) {
    fprintf(stderr, "UA2F_CALL_PROFILE {\"tcp4\":%llu,\"tcp6\":%llu,\"ip4\":%llu,\"mangle4\":%llu,\"mangle6\":%llu,\"sysconf\":%llu,\"pagesize\":%llu}\n", tcp4_calls, tcp6_calls, ip4_calls, mangle4_calls, mangle6_calls, sysconf_calls, pagesize_calls);
}
