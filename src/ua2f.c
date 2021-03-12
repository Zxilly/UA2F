#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef __USE_GNU
#define __USE_GNU
#endif

#include "ipset_hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <wait.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>


#include <libmnl/libmnl.h>
#include <libipset/ipset.h>
// #include <linux/netfilter.h>

#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <errno.h>

#define NF_ACCEPT 1


static struct mnl_socket *nl;
static const int queue_number = 10010;

static long long httpcount = 0;
static long long httpnouacount = 0;
static long long tcpcount = 0;
static long long httpmark = 0;
static long long nohttpmark = 0;
static long long oldhttpcount = 4;
static long long http1_0count = 0;

static time_t start_t, current_t;

static int debugflag = 0;
static int debugflag2 = 0;
static char timestr[60];

static struct ipset *Pipset;

static char *time2str(int sec) {
    memset(timestr, 0, sizeof(timestr));
    if (sec <= 60) {
        sprintf(timestr, "%d seconds", sec);
    } else if (sec <= 3600) {
        sprintf(timestr, "%d minutes and %d seconds", sec / 60, sec % 60);
    } else if (sec <= 86400) {
        sprintf(timestr, "%d hours, %d minutes and %d seconds", sec / 3600, sec % 3600 / 60, sec % 60);
    } else {
        sprintf(timestr, "%d days, %d hours, %d minutes and %d seconds", sec / 86400, sec % 86400 / 3600,
                sec % 3600 / 60,
                sec % 60);
    }
    return timestr;
}

static int parse_attrs(const struct nlattr *attr, void *data) {
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    tb[type] = attr;

    return MNL_CB_OK;
}

// static bool http_sign_check(bool firstcheck, unsigned int tcplen, unsigned char *tcppayload);

static bool stringCmp(const char *charp_to, const char charp_from[]) {
    return memcmp(charp_to, charp_from, strlen(charp_from)) == 0;
}

static int probe_http_method(const char *p, const char *opt) {
    return !strncmp(p, opt, strlen(opt));
}

static bool http_judge(char *tcppayload, unsigned int tcplen) {
//    if (*tcppayload < 65 || *tcppayload > 90) { // ASCII
//        return false;
//    }
//    switch (*tcppayload) {
//        case 'G':
//            return http_sign_check(stringCmp(tcppayload, "GET"), tcplen, tcppayload);
//        case 'P':
//            return http_sign_check(
//                    stringCmp(tcppayload, "POST") || stringCmp(tcppayload, "PUT") || stringCmp(tcppayload, "PATCH"),
//                    tcplen, tcppayload);
//        case 'C':
//            return stringCmp(tcppayload, "CONNECT"); // 这个应该有bug
//        case 'D':
//            return http_sign_check(stringCmp(tcppayload, "DELETE"), tcplen, tcppayload);
//        case 'H':
//            return http_sign_check(stringCmp(tcppayload, "HEAD"), tcplen, tcppayload);
//        case 'T':
//            return http_sign_check(stringCmp(tcppayload, "TRACE"), tcplen, tcppayload);
//        case 'O':
//            return http_sign_check(stringCmp(tcppayload, "OPTIONS"), tcplen, tcppayload);
//        default:
//            return false;
//    }

    if (tcplen <= 12) {
        return false;
    }

    if (memmem(tcppayload, tcplen, "HTTP", 4)) {
        return true;
    }

#define PROBE_HTTP_METHOD(option) if(probe_http_method(tcppayload, option)) {http1_0count++; return true;}

    /* Otherwise it could be HTTP/1.0 without version: check if it's got an
     * HTTP method (RFC2616 5.1.1) */
    PROBE_HTTP_METHOD("GET")
    PROBE_HTTP_METHOD("POST")
    PROBE_HTTP_METHOD("OPTIONS")
    PROBE_HTTP_METHOD("HEAD")
    PROBE_HTTP_METHOD("PUT")
    PROBE_HTTP_METHOD("DELETE")
    PROBE_HTTP_METHOD("TRACE")
    PROBE_HTTP_METHOD("CONNECT")

#undef PROBE_HTTP_METHOD

    return false;
}

/*static bool http_sign_check(bool firstcheck, const unsigned int tcplen, unsigned char *tcppayload) {
    if (!firstcheck) {
        return false;
    } else {
        for (int i = 14; i < tcplen - 3; i++) { //最短的 http 动词是 GET
            if (*(tcppayload + i) == '\r') {
                if (*(tcppayload + i + 1) == '\n') {
                    return stringCmp(tcppayload + i - 8, "HTTP/1"); // 向前查找 http 版本
                } else {
                    return false;
                }
            }
        } // 找不到 http 协议版本
        return false;
    }
}*/

static void
nfq_send_verdict(int queue_num, uint32_t id, struct pkt_buff *pktb, uint32_t mark, bool nohttp,
                 char addcmd[50]) { // http mark = 24, ukn mark = 18-20, no http mark = 23
    char buf[0xffff + (MNL_SOCKET_BUFFER_SIZE / 2)];
    struct nlmsghdr *nlh;
    struct nlattr *nest;
    uint32_t setmark;

    debugflag2 = 0;
    debugflag2++;//flag1

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

    debugflag2++;//flag2

    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }

    debugflag2++;//flag3


    if (nohttp) {
        if (mark == 1) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(16));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark >= 16 && mark <= 20) {
            setmark = mark + 1;
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark == 21) { // 21 统计确定此连接为非http连接

            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(23));
            mnl_attr_nest_end(nlh, nest); // 加 CONNMARK

            ipset_parse_line(Pipset, addcmd); //加 ipset 标记

            nohttpmark++;
        }
    } else {
        if (mark != 24) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(24));
            mnl_attr_nest_end(nlh, nest);
            httpmark++;
        }
    }


    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        //exithandle(1);
        syslog(LOG_ERR, "Exit at breakpoint 1.");
        exit(EXIT_FAILURE);
    }

    debugflag2++;//flag4

    tcpcount++;
    if (pktb) {
        pktb_free(pktb);
    }
    debugflag2++;//flag5
}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    struct nlattr *ctattr[CTA_MAX + 1] = {};
    struct nlattr *originattr[CTA_TUPLE_MAX + 1] = {};
    struct nlattr *ipattr[CTA_IP_MAX + 1] = {};
    struct nlattr *portattr[CTA_PROTO_MAX + 1] = {};
    uint16_t plen;
    struct pkt_buff *pktb;
    struct iphdr *ippkhdl;
    struct tcphdr *tcppkhdl;
    struct nfgenmsg *nfg;
    char *tcppkpayload;
    unsigned int tcppklen;
    unsigned int uaoffset = 0;
    unsigned int ualength = 0;
    char *str = NULL;
    void *payload;
    uint32_t mark = 0;
    bool nohttp = false;
    char *ip;
    uint16_t port = 0;

    char addcmd[50];


    debugflag = 0;


    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        // fputs("metaheader not set\n", stderr);
        syslog(LOG_ERR,"metaheader not set");
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_CT]) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctattr);

        if (ctattr[CTA_MARK]) {
            mark = ntohl(mnl_attr_get_u32(ctattr[CTA_MARK]));
        } else {
            mark = 1; // no mark 1
        } // NFQA_CT 一定存在，不存在说明有其他问题

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


    debugflag++; //1

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    debugflag++; //2

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);


    debugflag++; //3

    pktb = pktb_alloc(AF_INET, payload, plen, 0); //IP包

    if (!pktb) {
        syslog(LOG_ERR,"pktb malloc failed");
        return MNL_CB_ERROR;
    }

    debugflag++; //4

    ippkhdl = nfq_ip_get_hdr(pktb); //获取ip header

    if (nfq_ip_set_transport_header(pktb, ippkhdl) < 0) {
        syslog(LOG_ERR,"set transport header failed");
        pktb_free(pktb);
        return MNL_CB_ERROR;
    }


    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl, pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl, pktb); //获取 tcp长度

    if (tcppkpayload) {
        if (http_judge(tcppkpayload, tcppklen)) {
            debugflag++; //flag5

            char *uapointer = memmem(tcppkpayload, tcppklen, "User-Agent:", 11);

            debugflag++; //flag6

            if (uapointer) {
                uaoffset = uapointer - tcppkpayload + 12;

                for (int i = 0; i < tcppklen - uaoffset; ++i) {
                    if (*(uapointer + 12 + i) == '\r') {
                        ualength = i;
                        break;
                    }
                }
            } else {
                httpnouacount++;
            }

            debugflag++; //flag7

            if (uaoffset && ualength) {
                str = malloc(ualength);
                if (!str) {
                    pktb_free(pktb);
                    return MNL_CB_ERROR;
                }
                memset(str, 'F', ualength);
                if (nfq_tcp_mangle_ipv4(pktb, uaoffset, ualength, str, ualength) == 1) {
                    httpcount++; //记录修改包的数量
                    free(str);//用完就丢
                    nohttp = false;
                } else {
                    free(str);
                    pktb_free(pktb);
                    return MNL_CB_ERROR;
                }
            }

            debugflag++; //flag8
        } else {
            nohttp = true;
        }
    }

    debugflag++; //flag5 / 9

    nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, nohttp, addcmd);

    debugflag++; //flag6 / 10

    if (httpcount / oldhttpcount == 2 || httpcount - oldhttpcount >= 8192) {
        oldhttpcount = httpcount;
        current_t = time(NULL);
        syslog(LOG_INFO,
               "UA2F has handled %lld http, %lld http 1.0, %lld noua http, %lld tcp. Set %lld mark and %lld nohttp mark in %s",
               httpcount, http1_0count, httpnouacount, tcpcount, httpmark, nohttpmark,
               time2str((int) difftime(current_t, start_t)));
    }

    debugflag++;//flag7 / 11

    return MNL_CB_OK;
}

static void debugfunc() {
    syslog(LOG_ERR, "Catch SIGSEGV at breakpoint %d and breakpoint2 %d", debugflag, debugflag2);
    mnl_socket_close(nl);
    syslog(LOG_ALERT, "Meet fatal error, try to restart.");
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    char *buf;
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid;
    int child_status;

    int errcount = 0;

    signal(SIGSEGV, debugfunc);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    while (true) {
        child_status = fork();
        if (child_status < 0) {
            syslog(LOG_ERR, "Failed to give birth.");
            syslog(LOG_ERR, "Exit at breakpoint 2.");
            exit(EXIT_FAILURE);
        } else if (child_status == 0) {
            syslog(LOG_NOTICE, "UA2F processor start at [%d].", getpid());
            break;
        } else {
            syslog(LOG_NOTICE, "Try to start UA2F processor at [%d].", child_status);
            int deadstat;
            int deadpid;
            deadpid = wait(&deadstat);
            if (deadpid == -1) {
                syslog(LOG_ERR, "Child sucide.");
            } else {
                syslog(LOG_ERR, "Meet fatal error.[%d] dies by %d", deadpid, deadstat);
            }
        }
        errcount++;
        if (errcount > 50) {
            syslog(LOG_ERR, "Meet too many fatal error, no longer try to recover.");
            syslog(LOG_ERR, "Exit at breakpoint 3.");
            exit(EXIT_FAILURE);
        }
    }


    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    start_t = time(NULL);

    ipset_load_types();
    Pipset = ipset_init();

    if (!Pipset) {
        syslog(LOG_ERR, "Pipset not inited.");
        exit(EXIT_FAILURE);
    }

    ipset_custom_printf(Pipset, func, func2, func3, NULL); // hook 掉退出的输出函数

    syslog(LOG_NOTICE, "Pipset inited.");

    nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == NULL) {
        perror("mnl_socket_open");
        syslog(LOG_ERR, "Exit at breakpoint 4.");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        syslog(LOG_ERR, "Exit at breakpoint 5.");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    buf = malloc(sizeof_buf);
    if (!buf) {
        perror("allocate receive buffer");
        syslog(LOG_ERR, "Exit at breakpoint 6.");
        exit(EXIT_FAILURE);
    }

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
        syslog(LOG_ERR, "Exit at breakpoint 8.");
        exit(EXIT_FAILURE);
    }

    ret = 1;
    mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

    syslog(LOG_NOTICE, "UA2F has inited successful.");

    while (1) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) { //stop at failure
            perror("mnl_socket_recvfrom");
            syslog(LOG_ERR, "Exit at breakpoint 9.");
            exit(EXIT_FAILURE);
        }
        debugflag++; //1 或 16
        ret = mnl_cb_run(buf, ret, 0, portid, (mnl_cb_t) queue_cb, NULL);
        debugflag++; //15
        if (ret < 0) { //stop at failure
            // printf("errno=%d\n", errno);
            perror("mnl_cb_run");
            syslog(LOG_ERR, "Exit at breakpoint 10.");
            exit(EXIT_FAILURE);
        }
    }
}
