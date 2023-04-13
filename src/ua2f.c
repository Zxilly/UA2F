#include "statistics.h"
#include "util.h"
#include "child.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>


#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>

#define NF_ACCEPT 1

static struct mnl_socket *nl;
const int queue_number = 10010;

char *replacement_user_agent_string = NULL;

static int parse_attrs(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    tb[type] = attr;

    return MNL_CB_OK;
}

static void
nfq_send_verdict(int queue_num, uint32_t id, struct pkt_buff *pktb, uint32_t mark, bool noUA,
                 char addcmd[50]) { // http mark = 24, ukn mark = 16-20, no http mark = 23
    char buf[0xffff + (MNL_SOCKET_BUFFER_SIZE / 2)];
    struct nlmsghdr *nlh;
    struct nlattr *nest;
    uint32_t setmark;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, (int) id, NF_ACCEPT);

    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }


    if (noUA) {
        if (mark == 1) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(16));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark >= 16 && mark <= 40) {
            setmark = mark + 1;
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark == 41) { // 21 统计确定此连接为不含UA连接

            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(43));
            mnl_attr_nest_end(nlh, nest); // 加 CONNMARK

            count_packet_without_user_agent_mark();
        }
    } else {
        if (mark != 44) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(44));
            mnl_attr_nest_end(nlh, nest);
            count_packet_with_user_agent_mark();
        }
    }


    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 1.");
        exit(EXIT_FAILURE);
    }

    count_tcp_packet();
    pktb_free(pktb);
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    struct nlattr *ctattr[CTA_MAX + 1] = {};
    struct nlattr *originattr[CTA_TUPLE_MAX + 1] = {};
    struct nlattr *ipattr[CTA_IP_MAX + 1] = {};
    struct nlattr *portattr[CTA_PROTO_MAX + 1] = {};
    uint16_t payloadLength;
    struct pkt_buff *pktb;
    struct iphdr *ippkhdl;
    struct tcphdr *tcppkhdl;
    struct nfgenmsg *nfg;
    char *tcppkpayload;
    unsigned int tcppklen;
    unsigned int uaoffset = 0;
    unsigned int ualength = 0;
    void *payload;
    uint32_t mark = 0;
    bool noUA = false;
    char *ip;
    uint16_t port = 0;
    char addcmd[50];

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        syslog(LOG_ERR, "metaheader not set");
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_CT]) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctattr);

        if (ctattr[CTA_MARK]) {
            mark = ntohl(mnl_attr_get_u32(ctattr[CTA_MARK]));
        } else {
            mark = 1; // no mark 1
        }

        if (ctattr[CTA_TUPLE_ORIG]) {
            mnl_attr_parse_nested(ctattr[CTA_TUPLE_ORIG], parse_attrs, originattr);
            if (originattr[CTA_TUPLE_IP]) {
                mnl_attr_parse_nested(originattr[CTA_TUPLE_IP], parse_attrs, ipattr);
                if (ipattr[CTA_IP_V4_DST]) {
                    uint32_t tmp = mnl_attr_get_u32(ipattr[CTA_IP_V4_DST]);
                    struct in_addr tmp2;
                    tmp2.s_addr = tmp;
                    ip = inet_ntoa(tmp2);
                } else {
                    ip = "0.0.0.0";
                }
            } else {
                ip = "0.0.0.0";
            }
            if (originattr[CTA_TUPLE_PROTO]) {
                mnl_attr_parse_nested(originattr[CTA_TUPLE_PROTO], parse_attrs, portattr);
                if (portattr[CTA_PROTO_DST_PORT]) {
                    port = ntohs(mnl_attr_get_u16(portattr[CTA_PROTO_DST_PORT]));
                }
            }
            if (ip && port != 0) {
                sprintf(addcmd, "add nohttp %s,%d", ip, port);
            }
        }
    }

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    payloadLength = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);


    pktb = pktb_alloc(AF_INET, payload, payloadLength, 0); //IP包

    if (!pktb) {
        syslog(LOG_ERR, "pktb malloc failed");
        return MNL_CB_ERROR;
    }

    ippkhdl = nfq_ip_get_hdr(pktb); //获取ip header

    if (nfq_ip_set_transport_header(pktb, ippkhdl) < 0) {
        syslog(LOG_ERR, "set transport header failed");
        pktb_free(pktb);
        return MNL_CB_ERROR;
    }


    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl, pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl, pktb); //获取 tcp长度

    if (tcppkpayload) {
        char *uapointer = memncasemem(tcppkpayload, tcppklen, "\r\nUser-Agent: ", 14); // 找到指向 \r 的指针

        if (uapointer) {
            uaoffset = uapointer - tcppkpayload + 14; // 应该指向 UA 的第一个字符

            if (uaoffset >= tcppklen - 2) { // User-Agent: XXX\r\n
                syslog(LOG_WARNING, "User-Agent has no content");
                // https://github.com/Zxilly/UA2F/pull/42#issue-1159773997
                nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA, addcmd);
                return MNL_CB_OK;
            }

            char *uaStartPointer = uapointer + 14;
            const unsigned int uaLengthBound = tcppklen - uaoffset;
            for (unsigned int i = 0; i < uaLengthBound; ++i) {
                if (*(uaStartPointer + i) == '\r') {
                    ualength = i;
                    break;
                }
            }

            if (ualength > 0) {
                if (nfq_tcp_mangle_ipv4(pktb, uaoffset, ualength, replacement_user_agent_string, ualength) == 1) {
                    count_user_agent_packet();
                } else {
                    syslog(LOG_ERR, "Mangle packet failed.");
                    pktb_free(pktb);
                    return MNL_CB_ERROR;
                }
            }
        } else {
            noUA = true;
        }
    }

    nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, noUA, addcmd);

    return MNL_CB_OK;
}

int main(int argc, char *argv[]) {
    char *buf;

    struct nlmsghdr *nlh;
    ssize_t ret;
    unsigned int portid;

    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    works_as_child();

    init_statistics();

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == NULL) {
        perror("mnl_socket_open");
        syslog(LOG_ERR, "Exit at mnl_socket_open.");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        syslog(LOG_ERR, "Exit at mnl_socket_bind.");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    buf = malloc(MNL_SOCKET_BUFFER_SIZE);
    if (!buf) {
        syslog(LOG_ERR, "Failed to allocate buffer memory.");
        exit(EXIT_FAILURE);
    }

    replacement_user_agent_string = malloc(MNL_SOCKET_BUFFER_SIZE);
    memset(replacement_user_agent_string, 'F', MNL_SOCKET_BUFFER_SIZE);

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at breakpoint 7.");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_FLAGS,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32_check(nlh, MNL_SOCKET_BUFFER_SIZE, NFQA_CFG_MASK,
                           htonl(NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_CONNTRACK));


    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        syslog(LOG_ERR, "Exit at mnl_socket_send.");
        exit(EXIT_FAILURE);
    }

    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    syslog(LOG_NOTICE, "UA2F has inited successful.");

    while (1) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) { //stop at failure
            perror("mnl_socket_recvfrom");
            syslog(LOG_ERR, "Exit at mnl_socket_recvfrom.");
            exit(EXIT_FAILURE);
        }
        ret = mnl_cb_run(buf, ret, 0, portid, (mnl_cb_t) queue_cb, NULL);
        if (ret < 0) { //stop at failure
            perror("mnl_cb_run");
            syslog(LOG_ERR, "Exit at mnl_cb_run.");
            exit(EXIT_FAILURE);
        }
    }
}
