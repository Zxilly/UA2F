#ifdef UA2F_HAS_PCAP

#include "pcap_helpers.h"

#include <cstring>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

std::vector<pcap_tcp_packet> load_pcap_tcp_packets(const std::string &path) {
    std::vector<pcap_tcp_packet> result;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcap = pcap_open_offline(path.c_str(), errbuf);
    if (pcap == nullptr) {
        return result;
    }

    int link_type = pcap_datalink(pcap);

    struct pcap_pkthdr *header;
    const u_char *data;
    while (pcap_next_ex(pcap, &header, &data) == 1) {
        size_t eth_hdr_len = 0;
        uint16_t ether_type = 0;

        if (link_type == DLT_EN10MB) {
            if (header->caplen < 14) continue;
            ether_type = ntohs(*reinterpret_cast<const uint16_t *>(data + 12));
            eth_hdr_len = 14;
        } else if (link_type == DLT_RAW) {
            if (header->caplen < 1) continue;
            uint8_t version = (data[0] >> 4) & 0xf;
            ether_type = (version == 4) ? ETH_P_IP : ETH_P_IPV6;
            eth_hdr_len = 0;
        } else if (link_type == DLT_LINUX_SLL) {
            if (header->caplen < 16) continue;
            ether_type = ntohs(*reinterpret_cast<const uint16_t *>(data + 14));
            eth_hdr_len = 16;
        } else {
            continue;
        }

        if (ether_type != ETH_P_IP && ether_type != ETH_P_IPV6) continue;

        const u_char *ip_data = data + eth_hdr_len;
        size_t ip_len = header->caplen - eth_hdr_len;

        // Check for TCP
        if (ether_type == ETH_P_IP) {
            if (ip_len < sizeof(struct iphdr)) continue;
            auto *ip = reinterpret_cast<const struct iphdr *>(ip_data);
            if (ip->protocol != IPPROTO_TCP) continue;
        } else {
            if (ip_len < sizeof(struct ip6_hdr)) continue;
            auto *ip6 = reinterpret_cast<const struct ip6_hdr *>(ip_data);
            if (ip6->ip6_nxt != IPPROTO_TCP) continue;
        }

        pcap_tcp_packet pkt;
        pkt.ip_version = (ether_type == ETH_P_IP) ? IPV4 : IPV6;
        pkt.ip_bytes.assign(ip_data, ip_data + ip_len);
        result.push_back(std::move(pkt));
    }

    pcap_close(pcap);
    return result;
}

struct nf_packet make_nf_packet_from_pcap(const pcap_tcp_packet &pcap_pkt, uint32_t packet_id) {
    struct nf_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    pkt.packet_id = packet_id;
    pkt.queue_num = 10010;
    pkt.payload_len = pcap_pkt.ip_bytes.size();
    pkt.payload = malloc(pcap_pkt.ip_bytes.size());
    memcpy(pkt.payload, pcap_pkt.ip_bytes.data(), pcap_pkt.ip_bytes.size());
    pkt.has_conntrack = false;

    if (pcap_pkt.ip_version == IPV4) {
        pkt.hw_protocol = ETH_P_IP;
    } else {
        pkt.hw_protocol = ETH_P_IPV6;
    }

    return pkt;
}

#endif // UA2F_HAS_PCAP
