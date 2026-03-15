#ifndef UA2F_PCAP_HELPERS_H
#define UA2F_PCAP_HELPERS_H

#ifdef UA2F_HAS_PCAP

#include <vector>
#include <string>
#include <cstdint>

extern "C" {
#include "third/nfqueue-mnl/nfqueue-mnl.h"
}

struct pcap_tcp_packet {
    int ip_version; // IPV4 or IPV6
    std::vector<uint8_t> ip_bytes; // Raw IP packet (no ethernet header)
};

// Load TCP packets from a pcap file, stripping ethernet headers
std::vector<pcap_tcp_packet> load_pcap_tcp_packets(const std::string &path);

// Create an nf_packet from a loaded pcap packet (caller must free pkt.payload)
struct nf_packet make_nf_packet_from_pcap(const pcap_tcp_packet &pcap_pkt, uint32_t packet_id);

#endif // UA2F_HAS_PCAP
#endif // UA2F_PCAP_HELPERS_H
