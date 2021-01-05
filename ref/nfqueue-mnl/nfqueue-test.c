/*
 *  nfqueue-test - example program using nfqueue-mnl.h
 *  Copyright (c) 2019 Maciej Puzio
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program - see the file COPYING.
 */

#include "nfqueue-mnl.h"

#include <arpa/inet.h>  //inet_ntop
#include <linux/netfilter/nf_conntrack_common.h>  //IP_CT_* constants


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Helpers


//Note: ctime() returns trailing newline, thus we need special handling to chop it
static char* time_to_str(int64_t time)
{
    int64_t t = time;
    char* retval = strdup(ctime(&t));
    ASSERT(retval != NULL);
    size_t len = strlen(retval);
    ASSERT(len > 0);
    retval[len-1] = '\0';
    return retval;
}


static char* ip_to_str(ip_address_t* ip, int ip_version)
{
    ASSERT(ip_version == IPV4 || ip_version == IPV6);
    char* ip_buf = NULL;
    const char* retval = NULL;

    if (ip_version == IPV4)
    {
        ip_buf = malloc(INET_ADDRSTRLEN);
        ASSERT(ip_buf != NULL);
        retval = inet_ntop(AF_INET,  &ip->in4, ip_buf, INET_ADDRSTRLEN);
    }
    else if (ip_version == IPV6)
    {
        ip_buf = malloc(INET6_ADDRSTRLEN);
        ASSERT(ip_buf != NULL);
        retval = inet_ntop(AF_INET6, &ip->in6, ip_buf, INET6_ADDRSTRLEN);
    }

    ASSERT(retval != NULL);
    return ip_buf;
}


static char* conn_state_str(uint32_t state)
{
    switch(state)
    {
        case IP_CT_NEW:               return "new";
        case IP_CT_ESTABLISHED:       return "established";
        case IP_CT_RELATED:           return "related";
        case IP_CT_NEW_REPLY:         return "new-reply";
        case IP_CT_ESTABLISHED_REPLY: return "established-reply";
        case IP_CT_RELATED_REPLY:     return "related-reply";
        default:                      return "*unknown*";
    }
}


static void print_conn_status(uint32_t status)
{
    printf("  Status:%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
        status & IPS_EXPECTED?      " exp"   : "",
        status & IPS_SEEN_REPLY?    " reply" : "",
        status & IPS_ASSURED?       " assrd" : "",
        status & IPS_CONFIRMED?     " conf"  : "",
        status & IPS_SRC_NAT?       " snat"  : "",
        status & IPS_DST_NAT?       " dnat"  : "",
        status & IPS_SRC_NAT_DONE?  " snat!" : "",
        status & IPS_DST_NAT_DONE?  " dnat!" : "",
        status & IPS_SEQ_ADJUST?    " seq"   : "",
        status & IPS_DYING?         " dying" : "",
        status & IPS_FIXED_TIMEOUT? " tmfix" : "",
        status & IPS_TEMPLATE?      " templ" : "",
        status & IPS_UNTRACKED?     " untrk" : "",
        status & IPS_HELPER?        " help"  : "");
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Dump packet info from NetFilter


static void print_packet(struct nf_packet* p)
{
    printf("Netlink packet --------------\n");
    printf("  ID=%u Queue=%d PayLen=%lu Proto=%04x Family=%s\n",
        p->packet_id, p->queue_num, p->payload_len, p->hw_protocol,
        p->has_conntrack? (p->orig.ip_version == IPV4? "IPv4": p->orig.ip_version == IPV6? "IPv6": "UNRECOGNIZED") : "N/A");
    printf("  Optional:%s%s%s\n", p->has_timestamp? " ts" : "", p->has_conntrack? " ct" : "", p->has_connmark? " cm" : "");
    if (p->has_timestamp)
    {
        char* time_str = time_to_str(p->timestamp.tv_sec);
        printf("  NF timestamp: %lu.%06lu  %s\n", p->timestamp.tv_sec, p->timestamp.tv_usec, time_str);
        free(time_str);
    }
    else
    {
        printf("  NF timestamp: ABSENT\n");
    }
    char* wall_str = time_to_str(p->wall_time.tv_sec);
    printf("  My timestamp: %lu.%06lu  %s\n", p->wall_time.tv_sec, p->wall_time.tv_nsec / 1000, wall_str);
    free(wall_str);
    if (p->has_conntrack)
    {
        printf("  Conntrack: ID=%x ", p->conn_id);
        if (p->has_connmark)
            printf("Mark=%u ", p->conn_mark);
        else
            printf("Mark=ABSENT ");
        printf("State=%s\n", conn_state_str(p->conn_state));
        print_conn_status(p->conn_status);
        char* src_str = ip_to_str(&p->orig.src, p->orig.ip_version);
        char* dst_str = ip_to_str(&p->orig.dst, p->orig.ip_version);
        printf("  Src: %s port %u\n", src_str, p->orig.src_port);
        printf("  Dst: %s port %u\n", dst_str, p->orig.dst_port);
        free(src_str);
        free(dst_str);
    }
    else
    {
        printf("  Conntrack: ABSENT\n");
    }
    printf("-----------------------------\n");
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Main loop


int main(int argc, const char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s queue-num\n", argv[0]);
        DIE();
    }

    int queue_num = atoi(argv[1]);

    struct nf_queue queue[1];
    memset(queue, 0, sizeof(struct nf_queue));
    struct nf_buffer buf[1];
    memset(buf, 0, sizeof(struct nf_buffer));
    uint64_t packet_count = 0;

    if (!nfqueue_open(queue, queue_num, 0))
    {
        LOG(LOG_CRIT, "Can't open nfqueue");
        DIE();
    }

    for(;;)
    {
        if (nfqueue_receive(queue, buf, 0) == IO_READY)
        {
            struct nf_packet packet[1];
            while (nfqueue_next(buf, packet) == IO_READY)
            {
                LOG(LOG_INFO, "Packet count: %lu", ++packet_count);
                print_packet(packet);
                //Send accept verdict and set packet count as connmark
                nfqueue_verdict(queue, packet->packet_id, NF_ACCEPT, packet_count);
                free(packet->payload);
            }
        }
    }

    free(buf->data);
    nfqueue_close(queue);
}
