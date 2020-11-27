#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


const int queue_number = 10010;

static struct mnl_socket *nl;


static int queue_cb(const struct nlmsghdr *nlh, void *customdata)
{
    printf("cb called");

    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX+1] = {};
    uint32_t id = 0, skbinfo;
    struct nfgenmsg *nfg;
    uint16_t plen;

    if (nfq_nlmsg_parse(nlh, attr) == MNL_CB_ERROR) {
        perror("problems parsing");
        return MNL_CB_ERROR; //回调函数错误
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    /* void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]); */

//    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            printf("truncated ");
    }

//    if (skbinfo & NFQA_SKB_GSO) //NFQA_SKB_GSO为2，取倒数第二位
//        printf("GSO ");

    id = ntohl(ph->packet_id);
    if (ph->hw_protocol==IPPROTO_TCP){
        printf("get a TCP packet\n");
    }
    printf("packet received (id=%u hw=%u hook=%u, payload len %u",
           id, ntohs(ph->hw_protocol), ph->hook, plen);

    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
//    if (skbinfo & NFQA_SKB_CSUMNOTREADY) //NFQA_SKB_GSO为2，取倒数第二位
//        printf(", checksum not ready");
//    puts(")");

    return MNL_CB_OK;
}

int main(int argc, char *argv[])
{
    puts("aaaaaaaa");
    char *buf;
    /* largest possible packet payload, plus netlink data overhead: */
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    puts("bbbbbbbb");
    struct nlmsghdr *nlh;
    puts("cccccccc");
    int ret;
    unsigned int portid;

    printf("sign1");
    puts("sign1");

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    printf("sign2");
    puts("sign2");

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

    printf("sign3");
    puts("sign3");

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    printf("sign4");
    puts("sign4");

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

    printf("sign5");
    puts("sign5");

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    /* ENOBUFS is signalled to userspace when packets were lost
     * on kernel side.  In most cases, userspace isn't interested
     * in this information, so turn it off.
     */

    printf("sign6");
    puts("sign6");

    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    printf("sign7");
    puts("sign7");

    for (;;) {
        //printf("main loop");
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) {
            perror("mnl_socket_recvfrom");
            exit(EXIT_FAILURE);
        }

        ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
        if (ret < 0){
            perror("mnl_cb_run");
            exit(EXIT_FAILURE);
        }
    }

    mnl_socket_close(nl);

    return 0;
}