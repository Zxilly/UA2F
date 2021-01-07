//#include <errno.h>
//#include <wait.h>
//#include <sys/param.h>
//#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <wait.h>
#include <syslog.h>
#include <signal.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <errno.h>


#define NODEBUG

static struct mnl_socket *nl;
static const int queue_number = 10010;
static long long httpcount = 0;
static long long httpnouacount = 0;
static long long tcpcount = 0;
static long long httpmark = 0;
static long long nohttpmark = 0;
static long long oldhttpcount = 4;
static time_t start_t, current_t;

static int debugflag = 0;
static int debugflag2 = 0;
static char timestr[60];

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

static bool http_sign_check(bool firstcheck, unsigned int tcplen, unsigned char *tcppayload);

static bool stringCmp(unsigned char *charp_to, char charp_from[]) {
    return memcmp(charp_to, charp_from, strlen(charp_from)) == 0;

}

static bool http_judge(unsigned char *tcppayload, unsigned int tcplen) {
    if (*tcppayload < 65 || *tcppayload > 90) { // ASCII
        return false;
    }
    switch (*tcppayload) {
        case 'G':
            return http_sign_check(stringCmp(tcppayload, "GET"), tcplen, tcppayload);
        case 'P':
            return http_sign_check(
                    stringCmp(tcppayload, "POST") || stringCmp(tcppayload, "PUT") || stringCmp(tcppayload, "PATCH"),
                    tcplen, tcppayload);
        case 'C':
            return stringCmp(tcppayload, "CONNECT"); // 这个应该有bug
        case 'D':
            return http_sign_check(stringCmp(tcppayload, "DELETE"), tcplen, tcppayload);
        case 'H':
            return http_sign_check(stringCmp(tcppayload, "HEAD"), tcplen, tcppayload);
        case 'T':
            return http_sign_check(stringCmp(tcppayload, "TRACE"), tcplen, tcppayload);
        case 'O':
            return http_sign_check(stringCmp(tcppayload, "OPTIONS"), tcplen, tcppayload);
        default:
            return false;
    }
}

static bool http_sign_check(bool firstcheck, const unsigned int tcplen, unsigned char *tcppayload) {
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
}

static void
nfq_send_verdict(int queue_num, uint32_t id, struct pkt_buff *pktb, uint32_t mark,
                 bool nohttp) { // http mark = 24, ukn mark = 18-20, no http mark = 23
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

    // printf("get mark %u\n", mark);

    if (nohttp) {
        if (mark == 1) {
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(18));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark >= 18 && mark <= 20) {
            setmark = mark + 1;
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
            mnl_attr_nest_end(nlh, nest);
        }

        if (mark == 21) { // 21 统计确定此连接为非http连接
            nest = mnl_attr_nest_start(nlh, NFQA_CT);
            mnl_attr_put_u32(nlh, CTA_MARK, htonl(23));
            mnl_attr_nest_end(nlh, nest);
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

//    if (mark == 1) {
//        if (nohttp) {
//            setmark = 10; //非 http 流开始统计
//        } else {
//            setmark = 24; //http 流，必须处理，24
//            httpmark++;
//        }
//        nest = mnl_attr_nest_start(nlh, NFQA_CT);
//        mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
//        mnl_attr_nest_end(nlh, nest);
//        // printf("has set ctmark %u\n",setmark);
//    }
//
//    if (mark >= 10 && mark <= 20) {
//        setmark = mark + 1;
//        nest = mnl_attr_nest_start(nlh, NFQA_CT);
//        mnl_attr_put_u32(nlh, CTA_MARK, htonl(setmark));
//        mnl_attr_nest_end(nlh, nest);
//    }
//
//    if (mark == 21) { // 21 统计确定此连接为非http连接
//        nest = mnl_attr_nest_start(nlh, NFQA_CT);
//        mnl_attr_put_u32(nlh, CTA_MARK, htonl(23));
//        mnl_attr_nest_end(nlh, nest);
//    }

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
    uint16_t plen;
    struct pkt_buff *pktb;
    struct iphdr *ippkhdl;
    struct tcphdr *tcppkhdl;
    struct nfgenmsg *nfg;
    unsigned char *tcppkpayload;
    unsigned int tcppklen;
    unsigned int uaoffset = 0;
    unsigned int ualength = 0;
    char *str = NULL;
    void *payload;
    uint32_t mark = 0;
    bool nohttp = false;


    debugflag = 0;


    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_CT]) {
        mnl_attr_parse_nested(attr[NFQA_CT], parse_attrs, ctattr);
        if (ctattr[CTA_MARK]) {
            mark = ntohl(mnl_attr_get_u32(ctattr[CTA_MARK]));
        } else {
            mark = 1; // no mark 1
        }
    } // NFQA_CT 一定存在，不存在说明有其他问题


    debugflag++; //1

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    debugflag++; //2

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);


    debugflag++; //3

    pktb = pktb_alloc(AF_INET, payload, plen, 0); //IP包

    if (!pktb) {
        return MNL_CB_ERROR;
    }

    debugflag++; //4

    ippkhdl = nfq_ip_get_hdr(pktb); //获取ip header

    if (nfq_ip_set_transport_header(pktb, ippkhdl) < 0) {
        fputs("set transport header failed\n", stderr);
        pktb_free(pktb);
        return MNL_CB_ERROR;
    }


    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl, pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl, pktb); //获取 tcp长度

    if (tcppkpayload) {
        if (http_judge(tcppkpayload, tcppklen)) {
            for (unsigned int i = 0; i < tcppklen - 12; i++) { //UA长度大于12，结束段小于12不期望找到UA
                if (*(tcppkpayload + i) == '\n') {
                    if (*(tcppkpayload + i + 1) == '\r') {
                        httpnouacount++;
                        break; //http 头部结束，没有找到 User-Agent
                    } else {
                        if (stringCmp(tcppkpayload + i + 1, "User-Agent")) { //User-Agent: abcde
                            uaoffset = i + 13;
                            for (unsigned int j = i + 13; j < tcppklen; j++) {
                                if (*(tcppkpayload + j) == '\r') {
                                    ualength = j - i - 13;
                                    break;
                                }
                            }
                            break;
                        }
                    }
                }
            }
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
        } else {
            nohttp = true;
        }
    }

    debugflag++; //flag5


    nfq_send_verdict(ntohs(nfg->res_id), ntohl((uint32_t) ph->packet_id), pktb, mark, nohttp);


    debugflag++; //flag6

    if (httpcount / oldhttpcount == 2 || httpcount - oldhttpcount >= 8192) {
        oldhttpcount = httpcount;
        current_t = time(NULL);
        syslog(LOG_INFO, "UA2F has handled %lld http, %lld noua http, %lld tcp, %lld mark and %lld nohttp mark in %s",
               httpcount, httpnouacount, tcpcount, httpmark, nohttpmark,
               time2str((int) difftime(current_t, start_t)));
    }

    debugflag++;//flag7

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

#ifndef DEBUG
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
            wait(NULL);
            syslog(LOG_ERR, "Meet fatal error.");
        }
        errcount++;
        if (errcount > 50) {
            syslog(LOG_ERR, "Meet too many fatal error, no longer try to recover.");
            syslog(LOG_ERR, "Exit at breakpoint 3.");
            exit(EXIT_FAILURE);
        }
    }
#endif

    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    start_t = time(NULL);

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


    //mnl_socket_close(nl);


    //return 0;
}
