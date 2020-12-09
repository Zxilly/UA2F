//#include <errno.h>
//#include <wait.h>
//#include <sys/param.h>
//#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
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


/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>


static struct mnl_socket *nl;
static const int queue_number = 10010;
static long long httpcount = 0;
static long long httpnouacount = 0;
static long long tcpcount = 0;
static long long oldhttpcount = 4;
static time_t start_t, current_t;

static int debugflag = 0;
//static int debugflag2 = 0;


static _Bool stringCmp(const unsigned char *charp_to, const char charp_from[]) {
    int i = 0;
    while (charp_from[i] != '\0') {
        if (*(charp_to + i) != charp_from[i]) {
            return false;
        }
        i++;
    }
    return true;
}

static _Bool http_judge(const unsigned char *tcppayload) {
    switch (*tcppayload) {
        case 'G':
            return stringCmp(tcppayload, "GET");
        case 'P':
            return stringCmp(tcppayload, "POST") || stringCmp(tcppayload, "PUT") || stringCmp(tcppayload, "PATCH");
            /*case 'C':
                return stringCmp(tcppayload, "CONNECT"); // 这个应该有bug*/
        case 'D':
            return stringCmp(tcppayload, "DELETE");
        case 'H':
            return stringCmp(tcppayload, "HEAD");
        case 'T':
            return stringCmp(tcppayload, "TRACE");
        case 'O':
            return stringCmp(tcppayload, "OPTIONS");
        default:
            return false;
    }
}

static void nfq_send_verdict(int queue_num, uint32_t id, struct pkt_buff *pktb, int mark,
                             bool nohttp) { //http mark = 11 ,ukn mark = 12, http and ukn mark = 13
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;

    /*if (mark!=0){
        printf("get mark %d",mark);
    }*/

    if (nohttp) {
        mark = 12;
    } else {
        mark = 11;
    }


    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

    if (pktb_mangled(pktb)) {
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }

    mnl_attr_put_u32(nlh, NFQA_MARK, htonl(mark));

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    tcpcount++;
    pktb_free(pktb);

}

static int queue_cb(const struct nlmsghdr *nlh, void *data) {
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    uint32_t id;
    uint16_t plen;
    struct pkt_buff *pktb;
    struct iphdr *ippkhdl;
    struct tcphdr *tcppkhdl;
    struct nlattr *nest;
    struct nfgenmsg *nfg;
    unsigned char *tcppkpayload;
    unsigned int tcppklen;
    unsigned int uaoffset = 0;
    unsigned int ualength = 0;
    char *str = NULL;
    void *payload;
    bool nohttp = false;
    int mark;

    debugflag = 0;
    //debugflag2 = 0;


    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    nfg = mnl_nlmsg_get_payload(nlh);

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

    debugflag++; //1

    ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

    debugflag++; //2

    plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

    if (attr[NFQA_MARK]) {
        mark = mnl_attr_get_u32(attr[NFQA_MARK]);
    } else {
        mark = 0;
    }

    debugflag++; //3

    pktb = pktb_alloc(AF_INET, payload, plen, 0); //IP包

    if (!pktb) {
        return MNL_CB_ERROR;
    }

    debugflag++; //4

    ippkhdl = nfq_ip_get_hdr(pktb); //获取ip header

    if (nfq_ip_set_transport_header(pktb, ippkhdl) < 0) {
        fputs("set transport header failed\n", stderr);
        return MNL_CB_ERROR;
    }

    debugflag++; //5

    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl, pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl, pktb); //获取 tcp长度

    debugflag++; //6

    if (tcppkpayload) {
        if (http_judge(tcppkpayload)) {
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
                memset(str, 'F', ualength);
                if (nfq_tcp_mangle_ipv4(pktb, uaoffset, ualength, str, ualength) == 1) {
                    httpcount++; //记录修改包的数量
                }
                free(str);//用完就丢
            }
        } else {
            nohttp = true;
        }
    }

    debugflag++; //7


    debugflag++; //8

    id = ntohl(ph->packet_id);


    debugflag++; //9 FIXME: 非法内存访问

    debugflag++; //10

    debugflag++; //11

    nfq_send_verdict(ntohs(nfg->res_id), id, pktb, nohttp, mark);


//    free all space
//    struct nfqnl_msg_packet_hdr *ph = NULL;
//    struct nlattr *attr[NFQA_MAX + 1] = {};
//    uint32_t id;
//    uint16_t plen;
//    struct pkt_buff *pktb;
//    struct iphdr *ippkhdl;
//    struct tcphdr *tcppkhdl;
//    unsigned char *tcppkpayload;
//    unsigned int tcppklen;
//    unsigned int uaoffset = 0;
//    unsigned int ualength = 0;
//    char *str;
//    char buf[MNL_SOCKET_BUFFER_SIZE];
//    struct nlmsghdr *nlh2;
//    void *payload;

    debugflag++; //12

    debugflag++; //13

    if (httpcount / oldhttpcount == 2) {
        oldhttpcount = httpcount;
        current_t = time(NULL);
        syslog(LOG_INFO, "UA2F has handled %lld http packet, %lld http packet without ua and %lld tcp packet in %.0lfs",
               httpcount, httpnouacount, tcpcount,
               difftime(current_t, start_t));
    }

    debugflag++; //14


    return MNL_CB_OK;
}

static void debugfunc(int sig) {
    syslog(LOG_ERR, "Catch SIGSEGV at breakpoint %d", debugflag);
    //exit(EXIT_FAILURE);
    mnl_socket_close(nl);

    syslog(LOG_ALERT, "Meet fatal error, try to restart.");

    execlp("ua2f", "ua2f", NULL);
    //experimental restart

}

int main(int argc, char *argv[]) {
    char *buf;
    /* largest possible packet payload, plus netlink data overhead: */
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid;
    int startup_status;
    pid_t sid;

    if (argc > 1) {
        syslog(LOG_ALERT, "Rebirth process start");
    }

    signal(SIGSEGV, debugfunc); //handle内存断点

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN); // ignore 父进程挂掉的关闭信号
    startup_status = fork();
    if (startup_status < 0) {
        perror("Creat Daemon");
        closelog();
        exit(EXIT_FAILURE);
    } else if (startup_status == 0) {
        syslog(LOG_NOTICE, "UA2F parent daemon start at [%d].", getpid());
        sid = setsid();
        if (sid < 0) {
            perror("Second Dameon Claim");
            exit(EXIT_FAILURE);
        } else if (sid > 0) {
            syslog(LOG_NOTICE, "UA2F parent daemon set sid at [%d].", sid);
            startup_status = fork(); // 第二次fork，派生出一个孤儿
            if (startup_status < 0) {
                perror("Second Daemon Fork");
                exit(EXIT_FAILURE);
            } else if (startup_status > 0) {
                syslog(LOG_NOTICE, "UA2F true daemon will start at [%d], daemon parent suicide.", startup_status);
                exit(EXIT_SUCCESS);
            } else {
                syslog(LOG_NOTICE, "UA2F true daemon start at [%d].", getpid());
            }
        }
    } else {
        syslog(LOG_NOTICE, "UA2F try to start daemon parent at [%d], parent process will suicide.", startup_status);
        printf("UA2F try to start daemon parent at [%d], parent process will suicide.\n", startup_status);
        exit(EXIT_SUCCESS);
    }

    openlog("UA2F", LOG_PID, LOG_SYSLOG);

    start_t = time(NULL);

    //restart:

    nl = mnl_socket_open(NETLINK_NETFILTER);


    //syslog(LOG_NOTICE, "UA2F Daemon has start.");

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

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_number);
    nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

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

    syslog(LOG_NOTICE, "UA2F has inited successful.");

    while (1) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) { //stop at failure
            perror("mnl_socket_recvfrom");
            exit(EXIT_FAILURE);
            //continue;
            //break;
        }
        debugflag++; //1 或 16
        ret = mnl_cb_run(buf, ret, 0, portid, (mnl_cb_t) queue_cb, NULL);
        debugflag++; //15
        if (ret < 0) { //stop at failure
            perror("mnl_cb_run");
            exit(EXIT_FAILURE);
            //break;
        }
    }


    mnl_socket_close(nl);


    return 0;
}
