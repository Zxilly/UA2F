#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include <libmnl/libmnl.h>
#include <libipset/ipset.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


/* only for NFQA_CT, not needed otherwise: */

static char ipsetcmd[50] = "ipse";


static struct mnl_socket *nl;

static int parse_attrs(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    tb[type] = attr;

    return MNL_CB_OK;
}

static void nfq_send_verdict(int queue_num, uint32_t id) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nlattr *nest;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);


    nest = mnl_attr_nest_start(nlh, NFQA_CT);
    mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
    mnl_attr_nest_end(nlh, nest);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *nest;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    struct nlattr *ctattr[CTA_MAX + 1] = {};
    struct nlattr *originattr[CTA_TUPLE_MAX + 1] = {};
    struct nlattr *ipattr[CTA_IP_MAX + 1] = {};
    struct nlattr *portattr[CTA_PROTO_MAX + 1] = {};
    uint32_t id, skbinfo;
    struct nfgenmsg *nfg;
    uint16_t plen;
    uint32_t mark;

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }


    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            printf("truncated ");
    }


    if (attr[NFQA_CT]) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctattr);
        if (ctattr[CTA_TUPLE_ORIG]) {
            mnl_attr_parse_nested(ctattr[CTA_TUPLE_ORIG], parse_attrs, originattr);
            if (originattr[CTA_TUPLE_IP]) {
                mnl_attr_parse_nested(originattr[CTA_TUPLE_IP], parse_attrs, ipattr);
                if (ipattr[CTA_IP_V4_DST]){
                    uint32_t tmp = mnl_attr_get_u32(ipattr[CTA_IP_V4_DST]);
                    struct in_addr tmp2;
                    tmp2.s_addr = tmp;
                    char *ip = inet_ntoa(tmp2);
                }
            }
            if (originattr[CTA_TUPLE_PROTO]) {
                mnl_attr_parse_nested(originattr[CTA_TUPLE_PROTO], parse_attrs , portattr);
                if (portattr[CTA_PROTO_DST_PORT]){
                    uint16_t port = ntohs(mnl_attr_get_u16(portattr[CTA_PROTO_DST_PORT]));
                }
            }
        } else {
            printf("no ctattr[CTA_TUPLE_ORIG] ");
        }
    } else {
        printf("no attr[NFQA_CT] ");
    }




    id = ntohl(ph->packet_id);


    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
           id, ntohs(ph->hw_protocol), ph->hook, plen);
    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
    if (skbinfo & NFQA_SKB_CSUMNOTREADY)
        printf(", checksum not ready");
    puts(")");

    nfq_send_verdict(ntohs(nfg->res_id), id);

    return MNL_CB_OK;
}

int main(int argc, char *argv[]) {
    char *buf;
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid, queue_num;

    printf("5\n");

    queue_num = 10010;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    buf = malloc(sizeof_buf);
    if (!buf) {
        perror("allocate receive buffer");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_CONNTRACK));

    //mnl_attr_put_u32_check(nlh,MNL_SOCKET_BUFFER_SIZE,NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));
    //mnl_attr_put_u32_check(nlh,MNL_SOCKET_BUFFER_SIZE,NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    /* ENOBUFS is signalled to userspace when packets were lost
     * on kernel side.  In most cases, userspace isn't interested
     * in this information, so turn it off.
     */
    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));


    ipset_load_types();

    struct ipset *Pipset = ipset_init();


    for (;;) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) {
            perror("mnl_socket_recvfrom");
            exit(EXIT_FAILURE);
        }

        ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
        if (ret < 0) {
            perror("mnl_cb_run");
            exit(EXIT_FAILURE);
        }
    }

    mnl_socket_close(nl);

    return 0;
}
