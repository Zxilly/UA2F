#ifndef UA2F_HANDLER_H
#define UA2F_HANDLER_H

#include "packet_io.h"
#include "third/nfqueue-mnl/nfqueue-mnl.h"

#define CONNMARK_NOT_HTTP 43
#define CONNMARK_HTTP 44

extern bool use_conntrack;
extern const struct packet_io nfqueue_packet_io;

void init_handler();

void handle_packet(const struct packet_io *io, void *io_ctx, const struct nf_packet *pkt);

#endif // UA2F_HANDLER_H
