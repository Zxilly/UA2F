#ifndef UA2F_MOCK_PACKET_IO_H
#define UA2F_MOCK_PACKET_IO_H

#include <vector>
#include <cstdint>
#include <cstring>

extern "C" {
#include "packet_io.h"
#include <libnetfilter_queue/pktbuff.h>
}

struct recorded_verdict {
    uint32_t packet_id;
    int verdict;
    struct mark_op mark;
    std::vector<uint8_t> mangled_data;
};

struct mock_io_context {
    std::vector<recorded_verdict> verdicts;
};

static void mock_send_verdict(void *ctx, const struct nf_packet *pkt, int verdict,
                              struct mark_op mark, struct pkt_buff *mangled_pkt) {
    auto *mock = static_cast<mock_io_context *>(ctx);
    recorded_verdict v;
    v.packet_id = pkt->packet_id;
    v.verdict = verdict;
    v.mark = mark;
    if (mangled_pkt != nullptr) {
        const uint8_t *data = pktb_data(mangled_pkt);
        unsigned int len = pktb_len(mangled_pkt);
        if (data && len > 0) {
            v.mangled_data.assign(data, data + len);
        }
    }
    mock->verdicts.push_back(v);
}

static const struct packet_io mock_packet_io = {
    .send_verdict = mock_send_verdict,
};

#endif // UA2F_MOCK_PACKET_IO_H
