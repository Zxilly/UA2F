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
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/pktbuff.h>

/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>

static struct mnl_socket *nl;

static _Bool stringCmp(const unsigned char *charp_to,const char charp_from[]){
    int i = 0;
    while(charp_from[i]!='\0'){
        if (*(charp_to+i)!=charp_from[i]){
            return false;
        }
        i++;
    }
    return true;
}

static _Bool http_judge(const unsigned char *tcppayload){
    switch (*tcppayload) {
        case 'G':
            return stringCmp(tcppayload, "GET");
        case 'P':
            return stringCmp(tcppayload, "POST") || stringCmp(tcppayload, "PUT") || stringCmp(tcppayload, "PATCH");
        case 'C':
            return stringCmp(tcppayload, "CONNECT");
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

static char* getF(int len){
    char* str = (char *)malloc(len);
    return str;
}

static void nfq_send_verdict(int queue_num, uint32_t id) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nlattr *nest;

    nlh = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num);
    nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

    /* example to set the connmark. First, start NFQA_CT section: */
    //nest = mnl_attr_nest_start(nlh, NFQA_CT);

    /* then, add the connmark attribute: */
    //mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
    /* more conntrack attributes, e.g. CTA_LABELS could be set here */

    /* end conntrack section */
    //mnl_attr_nest_end(nlh, nest);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
}

static int queue_cb(struct nlmsghdr *nlh, void *data) {
    struct nfqnl_msg_packet_hdr *ph = NULL;
    struct nlattr *attr[NFQA_MAX + 1] = {};
    uint32_t id = 0, skbinfo;
    struct nfgenmsg *nfg;
    uint16_t plen;
    struct pkt_buff *pktb;
    struct iphdr *ippkhdl;
    struct tcphdr *tcppkhdl;
    unsigned char *tcppkpayload;
    unsigned int tcppklen;
    int uaoffset;
    int ualength;


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
    void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

    pktb = pktb_alloc(AF_INET, payload, plen, 255); //IP包

    ippkhdl = nfq_ip_get_hdr(pktb); //获取ip header

    if (nfq_ip_set_transport_header(pktb, ippkhdl) < 0) {
        fputs("set transport header failed\n", stderr);
        return MNL_CB_ERROR;
    }

    tcppkhdl = nfq_tcp_get_hdr(pktb); //获取 tcp header
    tcppkpayload = nfq_tcp_get_payload(tcppkhdl,pktb); //获取 tcp载荷
    tcppklen = nfq_tcp_get_payload_len(tcppkhdl,pktb); //获取 tcp长度

    if(tcppkpayload){
        for(int i = 0;i<tcppklen;i++){
            printf("%c",*(tcppkpayload+i));
        }
        printf("\n");
        if(http_judge(tcppkpayload)){
            printf("checked HTTP\n");
        }
        for(int i = 0;i<tcppklen;i++){
            if (*(tcppkpayload+i)=='\n'){
                if(*(tcppkpayload+i+1)=='\r'){
                    break; //http 头部结束，没有找到 User-Agent
                } else {
                    if(stringCmp(tcppkpayload+i+1,"User-Agent")){ //User-Agent: abcde
                        /*for(int j=13;j<tcppklen-i;j++){ //tcppayload+i+j
                            if (*(tcppkpayload+i+j)=='\r'){ //UA字段结束
                                printf("\n");
                                break;
                            } else {
                                printf("%c",*(tcppkpayload+i+j));
                            }
                        }*/
                        uaoffset=i+13;
                        for(int j=i+13;j<tcppklen;j++){
                            if (*(tcppkpayload+j)=='\r'){
                                ualength=j-i-13;
                            }
                        }
                    }
                }
            }
        }
        printf("ua offset %d and length %d",uaoffset,ualength);
        if(nfq_tcp_mangle_ipv4(pktb,uaoffset,ualength,getF(ualength),ualength)<0){
            perror("mangle packet");
        }
    }


    if (pktb_mangled(pktb)) {
        printf("modified\n");
        nfq_nlmsg_verdict_put_pkt(nlh, pktb_data(pktb), pktb_len(pktb));
    }

    skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

    if (attr[NFQA_CAP_LEN]) {
        uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
        if (orig_len != plen)
            printf("truncated ");
    }

    if (skbinfo & NFQA_SKB_GSO)
        printf("GSO ");

    id = ntohl(ph->packet_id);
    printf("packet received (id=%u hw=%u hook=%u, payload len %u",
           id, ntohs(ph->hw_protocol), ph->hook, plen);

    /*
     * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
     * The application should behave as if the checksums are correct.
     *
     * If these packets are later forwarded/sent out, the checksums will
     * be corrected by kernel/hardware.
     */
    if (skbinfo & NFQA_SKB_CSUMNOTREADY) { printf(", checksum not ready"); }
    puts(")");

    nfq_send_verdict(ntohs(nfg->res_id), id);

    return MNL_CB_OK;
}

int main(int argc, char *argv[]) {
    char *buf;
    /* largest possible packet payload, plus netlink data overhead: */
    size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE / 2);
    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid, queue_num = 10010;


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

    for (;;) {
        ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
        if (ret == -1) {
            perror("mnl_socket_recvfrom");
            exit(EXIT_FAILURE);
        }

        ret = mnl_cb_run(buf, ret, 0, portid, (mnl_cb_t) queue_cb, NULL);
        if (ret < 0) {
            perror("mnl_cb_run");
            exit(EXIT_FAILURE);
        }
    }

    mnl_socket_close(nl);

    return 0;
}
