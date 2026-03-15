#include "handler.h"
#include "packet_io.h"
#include "third/nfqueue-mnl/nfqueue-mnl.h"

#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <syslog.h>

static void nfqueue_send_verdict(void *ctx, const struct nf_packet *pkt, int verdict,
                                 const struct mark_op mark, struct pkt_buff *mangled_pkt_buff) {
    const struct nf_queue *queue = (const struct nf_queue *)ctx;
    assert(queue != NULL && "Queue cannot be NULL");
    assert(pkt != NULL && "Packet cannot be NULL");
    assert(queue->nl_socket != NULL && "Netlink socket cannot be NULL");

    struct nlmsghdr *nlh = nfqueue_put_header(pkt->queue_num, NFQNL_MSG_VERDICT);
    if (nlh == NULL) {
        syslog(LOG_ERR, "failed to put nfqueue header");
        goto end;
    }
    nfq_nlmsg_verdict_put(nlh, (int)pkt->packet_id, verdict);

    if (mark.should_set) {
        struct nlattr *nest = mnl_attr_nest_start_check(nlh, SEND_BUF_LEN, NFQA_CT);
        if (nest == NULL) {
            syslog(LOG_ERR, "failed to put nfqueue attr");
            goto end;
        }
        if (!mnl_attr_put_u32_check(nlh, SEND_BUF_LEN, CTA_MARK, htonl(mark.mark))) {
            syslog(LOG_ERR, "failed to put nfqueue attr");
            goto end;
        }
        mnl_attr_nest_end(nlh, nest);
    }

    if (mangled_pkt_buff != NULL) {
        assert(pktb_data(mangled_pkt_buff) != NULL && "Mangled packet data cannot be NULL");
        assert(pktb_len(mangled_pkt_buff) > 0 && "Mangled packet length must be positive");
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(mangled_pkt_buff), pktb_len(mangled_pkt_buff));
    }

    const __auto_type ret = mnl_socket_sendto(queue->nl_socket, nlh, nlh->nlmsg_len);
    if (ret == -1) {
        syslog(LOG_ERR, "failed to send verdict: %s", strerror(errno));
    }

end:
    if (nlh != NULL) {
        free(nlh);
    }
}

const struct packet_io nfqueue_packet_io = {
    .send_verdict = nfqueue_send_verdict,
};
