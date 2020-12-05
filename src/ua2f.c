//#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
//#include <wait.h>
#include <signal.h>
//#include <sys/param.h>
//#include <sys/stat.h>
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
static long long count = 0;
static long long oldcount = 4;
static time_t start_t, current_t;

static int debugflag = 0;
static int debugflag2 = 0;


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
        case 'C':
            return stringCmp(tcppayload, "CONNECT"); // 这个应该有bug
        case 'D':
            return stringCmp(tcppayload, "DELETE");
        case 'H':
            return stringCmp(tcppayload, "HEAD");
        case 'T':
            return stringCmp(tcppayload, "TRACE");
        case 'O':
            return stringCmp(tcppayload, "OPTIONS");
    }
    return false;
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
    unsigned char *tcppkpayload;
    unsigned int tcppklen;
    unsigned int uaoffset = 0;
    unsigned int ualength = 0;
    char *str = NULL;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh2;
    void *payload;
    bool nohttp = false;

    debugflag = 0;
    debugflag2 = 0;


    if (nfq_nlmsg_parse(nlh, attr) < 0) {
        perror("problems parsing");
        return MNL_CB_ERROR;
    }

    if (attr[NFQA_PACKET_HDR] == NULL) {
        fputs("metaheader not set\n", stderr);
        return MNL_CB_ERROR;
    }

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
        return MNL_CB_ERROR;
    }

    debugflag++; //5

    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl, pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl, pktb); //获取 tcp长度

    debugflag++; //6

    if (tcppkpayload) {
        /*for(int i = 0;i<tcppklen;i++){ //输出包头
            printf("%c",*(tcppkpayload+i));
            if(*(tcppkpayload+i)=='\n'&&*(tcppkpayload+i+1)=='\r'){
                break;
            }
        }*/
//        printf("\n");
        if (http_judge(tcppkpayload)) {
            //printf("checked HTTP\n");
            debugflag2++;//1
            for (unsigned int i = 0; i < tcppklen - 12; i++) { //UA长度大于12，结束段小于12不期望找到UA
                if (*(tcppkpayload + i) == '\n') {

                    if (*(tcppkpayload + i + 1) == '\r') {
                        break; //http 头部结束，没有找到 User-Agent
                    } else {
                        if (stringCmp(tcppkpayload + i + 1, "User-Agent")) { //User-Agent: abcde
                            /*for(int j=13;j<tcppklen-i;j++){ //tcppayload+i+j
                                if (*(tcppkpayload+i+j)=='\r'){ //UA字段结束
                                    printf("\n");
                                    break;
                                } else {
                                    printf("%c",*(tcppkpayload+i+j));
                                }
                            }*/
                            uaoffset = i + 13;
                            //puts("j_start");
                            for (unsigned int j = i + 13; j < tcppklen; j++) {
                                if (*(tcppkpayload + j) == '\r') {
                                    ualength = j - i - 13;
                                    //printf("uaend\n");
                                    //printf("\n");
                                    break;
                                }
                                //printf("%c",*(tcppkpayload+j));
                            }
                            //puts("j_stop");
                            break;
                        }
                    }
                }
            }
            if (uaoffset && ualength) {
                //printf("ua is exist");
                str = malloc(ualength);
                memset(str, 'F', ualength);
                /*for(int i=0;i<ualength;i++){ //测试替换 buf
                    printf("%c",*(str+i));
                }*/
                if (nfq_tcp_mangle_ipv4(pktb, uaoffset, ualength, str, ualength) == 1) {
                    //printf("\nsuccess mangle\n");
                    count++; //记录修改包的数量
                }
            }
            //printf("ua offset %d and length %d\n",uaoffset,ualength);

//            char *test = (char *)malloc(3);
//            *test = 'P';
//            *(test+1) = 'U';
//            *(test+2) = 'T';
            //nfq_tcp_mangle_ipv4(pktb,0,3,test,3);
            //tcppkpayload = nfq_tcp_get_payload(tcppkhdl,pktb); //检查pktb是否成功修改
            /*for(int i=0;i<tcppklen;i++){
                //printf("%c",*(tcppkpayload+i));
                if(*(tcppkpayload+i)=='\n'&&*(tcppkpayload+i+1)=='\r'){
                    break; //只输出HTTP包头
                }
            }*/
        } else {
            nohttp = true;
        }


        //nfq_tcp_mangle_ipv4(pktb,uaoffset,ualength,str,ualength);
    }

    debugflag++; //7

    nlh2 = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, 10010);
    if (pktb_mangled(pktb)) {
        //printf("modified\n");
        nfq_nlmsg_verdict_put_pkt(nlh2, pktb_data(pktb), pktb_len(pktb));
    }

    debugflag++; //8

    //skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    /*if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            printf("truncated ");
    }*/

    /*if (skbinfo & NFQA_SKB_GSO)
        printf("GSO ");*/

    id = ntohl(ph->packet_id);

    debugflag++; //9
//    printf("packet received (id=%u hw=%x hook=%u, payload len %u",
//           id, ntohs(ph->hw_protocol), ph->hook, plen);

    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
//    if (skbinfo & NFQA_SKB_CSUMNOTREADY) { printf(", checksum not ready"); }
//    puts(")");

    //nfq_send_verdict(10010, id);
    nfq_nlmsg_verdict_put(nlh2, id, NF_ACCEPT);

    debugflag++; //10

    if (nohttp) {
        /* example to set the connmark. First, start NFQA_CT section: */
        nest = mnl_attr_nest_start(nlh2, NFQA_CT);

        /* then, add the connmark attribute: */
        mnl_attr_put_u32(nlh2, CTA_MARK, htonl(42)); //CONNMARK 42 以匹配
        /* more conntrack attributes, e.g. CTA_LABELS could be set here */

        /* end conntrack section */
        mnl_attr_nest_end(nlh2, nest);
        //看起来不工作？
    }

    debugflag++; //11

    mnl_socket_sendto(nl, nlh2, nlh2->nlmsg_len);


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


    free(pktb);
    if (str) {
        free(str);
    }

    debugflag++; //13

    if (count / oldcount == 2) {
        oldcount = count;
        current_t = time(NULL);
        syslog(LOG_INFO, "UA2F has handled %lld http packet in %.0lfs", count, difftime(current_t, start_t));
    }

    debugflag++; //14

    return MNL_CB_OK;
}

static void debugfunc(int sig) {
    syslog(LOG_ERR, "Catch SIGSEGV at breakpoint %d and %d", debugflag,debugflag2);
    exit(EXIT_FAILURE);
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
    nl = mnl_socket_open(NETLINK_NETFILTER);
    start_t = time(NULL);

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
        if (ret == -233) { //keep running
            perror("mnl_socket_recvfrom");
            //exit(EXIT_FAILURE);
            //continue;
            break;
        }

        ret = mnl_cb_run(buf, ret, 0, portid, (mnl_cb_t) queue_cb, NULL);
        if (ret == -233) { //keep running
            perror("mnl_cb_run");
            //exit(EXIT_FAILURE);
            break;
        }
    }

    mnl_socket_close(nl);

    return 0;
}
