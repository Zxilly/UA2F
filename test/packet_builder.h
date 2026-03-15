#ifndef UA2F_PACKET_BUILDER_H
#define UA2F_PACKET_BUILDER_H

#include <cstdint>
#include <cstddef>
#include <vector>

extern "C" {
#include "third/nfqueue-mnl/nfqueue-mnl.h"
}

// Build a raw IPv4+TCP packet with given payload
std::vector<uint8_t> build_ipv4_tcp_packet(
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const void *payload, size_t payload_len);

// Build a raw IPv6+TCP packet with given payload
std::vector<uint8_t> build_ipv6_tcp_packet(
    const struct in6_addr &src_ip, const struct in6_addr &dst_ip,
    uint16_t src_port, uint16_t dst_port,
    const void *payload, size_t payload_len);

// Create an nf_packet from raw IP bytes (caller must free pkt.payload)
struct nf_packet make_nf_packet(const std::vector<uint8_t> &ip_bytes,
                                uint32_t packet_id, int ip_version);

// Create an nf_packet with conntrack fields populated
struct nf_packet make_nf_packet_with_conntrack(
    const std::vector<uint8_t> &ip_bytes,
    uint32_t packet_id, int ip_version,
    uint32_t conn_id,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port);

// Extract TCP payload from raw IP packet bytes
std::vector<uint8_t> extract_tcp_payload(const std::vector<uint8_t> &ip_bytes, int ip_version);

#endif // UA2F_PACKET_BUILDER_H
