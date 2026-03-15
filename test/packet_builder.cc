#include "packet_builder.h"

#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

std::vector<uint8_t> build_ipv4_tcp_packet(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const void *payload, size_t payload_len) {

    size_t ip_hdr_len = sizeof(struct iphdr);
    size_t tcp_hdr_len = sizeof(struct tcphdr);
    size_t total = ip_hdr_len + tcp_hdr_len + payload_len;

    std::vector<uint8_t> pkt(total, 0);

    auto *ip = reinterpret_cast<struct iphdr *>(pkt.data());
    ip->version = 4;
    ip->ihl = ip_hdr_len / 4;
    ip->tot_len = htons(total);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = src_ip;
    ip->daddr = dst_ip;

    // Compute IP header checksum
    uint32_t sum = 0;
    const uint16_t *p = reinterpret_cast<const uint16_t *>(ip);
    for (size_t i = 0; i < ip_hdr_len / 2; i++) {
        sum += ntohs(p[i]);
    }
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    ip->check = htons(~sum & 0xffff);

    auto *tcp = reinterpret_cast<struct tcphdr *>(pkt.data() + ip_hdr_len);
    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_off = tcp_hdr_len / 4;
    tcp->ack = 1;
    tcp->window = htons(65535);

    if (payload && payload_len > 0) {
        memcpy(pkt.data() + ip_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    return pkt;
}

std::vector<uint8_t> build_ipv6_tcp_packet(
    const struct in6_addr &src_ip, const struct in6_addr &dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const void *payload, size_t payload_len) {

    size_t ip6_hdr_len = sizeof(struct ip6_hdr);
    size_t tcp_hdr_len = sizeof(struct tcphdr);
    size_t total = ip6_hdr_len + tcp_hdr_len + payload_len;

    std::vector<uint8_t> pkt(total, 0);

    auto *ip6 = reinterpret_cast<struct ip6_hdr *>(pkt.data());
    ip6->ip6_flow = htonl(0x60000000); // version 6
    ip6->ip6_plen = htons(tcp_hdr_len + payload_len);
    ip6->ip6_nxt = IPPROTO_TCP;
    ip6->ip6_hlim = 64;
    memcpy(&ip6->ip6_src, &src_ip, sizeof(struct in6_addr));
    memcpy(&ip6->ip6_dst, &dst_ip, sizeof(struct in6_addr));

    auto *tcp = reinterpret_cast<struct tcphdr *>(pkt.data() + ip6_hdr_len);
    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_off = tcp_hdr_len / 4;
    tcp->ack = 1;
    tcp->window = htons(65535);

    if (payload && payload_len > 0) {
        memcpy(pkt.data() + ip6_hdr_len + tcp_hdr_len, payload, payload_len);
    }

    return pkt;
}

struct nf_packet make_nf_packet(const std::vector<uint8_t> &ip_bytes,
                                uint32_t packet_id, int ip_version) {
    struct nf_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.packet_id = packet_id;
    pkt.queue_num = 10010;
    pkt.payload_len = ip_bytes.size();
    pkt.payload = malloc(ip_bytes.size());
    memcpy(pkt.payload, ip_bytes.data(), ip_bytes.size());

    pkt.has_conntrack = false;
    if (ip_version == IPV4) {
        pkt.hw_protocol = ETH_P_IP;
    } else {
        pkt.hw_protocol = ETH_P_IPV6;
    }

    return pkt;
}

struct nf_packet make_nf_packet_with_conntrack(
    const std::vector<uint8_t> &ip_bytes,
    uint32_t packet_id, int ip_version,
    uint32_t conn_id,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port) {

    struct nf_packet pkt = make_nf_packet(ip_bytes, packet_id, ip_version);
    pkt.has_conntrack = true;
    pkt.conn_id = conn_id;
    pkt.orig.ip_version = ip_version;
    pkt.orig.src.ip4 = src_ip;
    pkt.orig.dst.ip4 = dst_ip;
    pkt.orig.src_port = src_port;
    pkt.orig.dst_port = dst_port;
    return pkt;
}

std::vector<uint8_t> extract_tcp_payload(const std::vector<uint8_t> &ip_bytes, int ip_version) {
    size_t ip_hdr_len;
    if (ip_version == IPV4) {
        if (ip_bytes.size() < sizeof(struct iphdr)) return {};
        auto *ip = reinterpret_cast<const struct iphdr *>(ip_bytes.data());
        ip_hdr_len = ip->ihl * 4;
    } else {
        ip_hdr_len = sizeof(struct ip6_hdr);
    }

    if (ip_bytes.size() < ip_hdr_len + sizeof(struct tcphdr)) return {};
    auto *tcp = reinterpret_cast<const struct tcphdr *>(ip_bytes.data() + ip_hdr_len);
    size_t tcp_hdr_len = tcp->th_off * 4;
    size_t payload_offset = ip_hdr_len + tcp_hdr_len;

    if (ip_bytes.size() <= payload_offset) return {};
    return std::vector<uint8_t>(ip_bytes.begin() + payload_offset, ip_bytes.end());
}
