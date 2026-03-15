#ifndef UA2F_PACKET_IO_H
#define UA2F_PACKET_IO_H

#include "third/nfqueue-mnl/nfqueue-mnl.h"
#include <libnetfilter_queue/pktbuff.h>
#include <stdbool.h>
#include <stdint.h>

struct mark_op {
    bool should_set;
    uint32_t mark;
};

struct packet_io {
    void (*send_verdict)(void *ctx, const struct nf_packet *pkt, int verdict,
                         struct mark_op mark, struct pkt_buff *mangled_pkt);
};

#endif // UA2F_PACKET_IO_H
