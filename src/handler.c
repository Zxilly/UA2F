#include "assert.h"
#include "handler.h"
#include "cache.h"
#include "custom.h"
#include "statistics.h"
#include "util.h"
#include "http_session.h"
#include "http_parser_ua.h"

#ifdef UA2F_ENABLE_UCI
#include "config.h"
#endif

#include <arpa/inet.h>
#include <linux/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/if_ether.h>

#define MAX_USER_AGENT_LENGTH (0xffff + (MNL_SOCKET_BUFFER_SIZE / 2))
static char *replacement_user_agent_string = NULL;

static const struct mark_op MARK_NONE = {false, 0};
static const struct mark_op MARK_NOT_HTTP = {true, CONNMARK_NOT_HTTP};
static const struct mark_op MARK_HTTP = {true, CONNMARK_HTTP};

#ifndef UA2F_NO_CACHE
bool use_conntrack = true;
#else
bool use_conntrack = false;
#endif

void init_handler() {
    init_not_http_cache(60);

    replacement_user_agent_string = malloc(MAX_USER_AGENT_LENGTH);
    assert(replacement_user_agent_string != NULL && "Failed to allocate user agent string");

    bool ua_set = false;

#ifdef UA2F_ENABLE_UCI
    if (config.use_custom_ua) {
        memset(replacement_user_agent_string, ' ', MAX_USER_AGENT_LENGTH);
        strncpy(replacement_user_agent_string, config.custom_ua, strlen(config.custom_ua));
        syslog(LOG_INFO, "Using config user agent string: %s", replacement_user_agent_string);
        ua_set = true;
    }

    if (config.disable_connmark) {
        use_conntrack = false;
        syslog(LOG_INFO, "Conntrack cache disabled by config.");
    }
#endif

#ifdef UA2F_CUSTOM_UA
    if (!ua_set) {
        memset(replacement_user_agent_string, ' ', MAX_USER_AGENT_LENGTH);
        strncpy(replacement_user_agent_string, UA2F_CUSTOM_UA, strlen(UA2F_CUSTOM_UA));
        syslog(LOG_INFO, "Using embed user agent string: %s", replacement_user_agent_string);
        ua_set = true;
    }
#endif

    if (!ua_set) {
        memset(replacement_user_agent_string, 'F', MAX_USER_AGENT_LENGTH);
        syslog(LOG_INFO, "Custom user agent string not set, using default F-string.");
    }

    syslog(LOG_INFO, "Handler initialized.");
}

void add_to_cache(const struct nf_packet *pkt) {
    const struct addr_port target = {
        .addr = pkt->orig.dst,
        .port = pkt->orig.dst_port,
    };

    cache_add(target);
}

bool should_ignore(const struct nf_packet *pkt) {
    bool retval = false;
    struct addr_port target = {
        .addr = pkt->orig.dst,
        .port = pkt->orig.dst_port,
    };

    retval = cache_contains(target);

    return retval;
}

enum {
    IP_UNK = 0,
};

bool ipv4_set_transport_header(struct pkt_buff *pkt_buff) {
    struct iphdr *ip_hdr = nfq_ip_get_hdr(pkt_buff);
    if (ip_hdr == NULL) {
        syslog(LOG_ERR, "Failed to get ipv4 ip header");
        return false;
    }

    if (nfq_ip_set_transport_header(pkt_buff, ip_hdr) == -1) {
        syslog(LOG_ERR, "Failed to set ipv4 transport header");
        return false;
    }
    return true;
}

bool ipv6_set_transport_header(struct pkt_buff *pkt_buff) {
    struct ip6_hdr *ip_hdr = nfq_ip6_get_hdr(pkt_buff);
    if (ip_hdr == NULL) {
        syslog(LOG_ERR, "Failed to get ipv6 ip header");
        return false;
    }

    if (nfq_ip6_set_transport_header(pkt_buff, ip_hdr, IPPROTO_TCP) == 0) {
        syslog(LOG_ERR, "Failed to set ipv6 transport header");
        return false;
    }
    return true;
}

int get_pkt_ip_version(const struct nf_packet *pkt) {
    if (pkt->has_conntrack) {
        return pkt->orig.ip_version;
    }

    switch (pkt->hw_protocol) {
    case ETH_P_IP:
        return IPV4;
    case ETH_P_IPV6:
        return IPV6;
    default:
        syslog(LOG_WARNING, "Received unknown ip packet %x.", pkt->hw_protocol);
        return IP_UNK;
    }
}

void handle_packet(const struct packet_io *io, void *io_ctx, const struct nf_packet *pkt) {
    assert(io != NULL && "Packet I/O cannot be NULL");
    assert(io->send_verdict != NULL && "send_verdict callback cannot be NULL");
    assert(pkt != NULL && "Packet cannot be NULL");
    assert(pkt->payload != NULL && "Packet payload cannot be NULL");
    assert(pkt->payload_len > 0 && "Packet payload length must be positive");

    struct pkt_buff *pkt_buff = NULL;
    bool ct_ok = use_conntrack && pkt->has_conntrack;

    // Level 1: cache check
    if (ct_ok && should_ignore(pkt)) {
        io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NOT_HTTP, NULL);
        goto end;
    }

    const int type = get_pkt_ip_version(pkt);
    if (type == IP_UNK) {
        syslog(LOG_WARNING, "Received unknown ip packet type %x. You may set wrong firewall rules.", pkt->hw_protocol);
        io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NONE, NULL);
        goto end;
    }

    pkt_buff = pktb_alloc(type == IPV4 ? AF_INET : AF_INET6, pkt->payload, pkt->payload_len, 0);
    if (pkt_buff == NULL) {
        syslog(LOG_ERR, "Failed to allocate packet buffer");
        goto end;
    }

    if (type == IPV4) {
        if (!ipv4_set_transport_header(pkt_buff)) {
            syslog(LOG_ERR, "Failed to set ipv4 transport header");
            goto end;
        }
        count_ipv4_packet();
    } else if (type == IPV6) {
        if (!ipv6_set_transport_header(pkt_buff)) {
            syslog(LOG_ERR, "Failed to set ipv6 transport header");
            goto end;
        }
        count_ipv6_packet();
    } else {
        syslog(LOG_ERR, "Unknown ip version");
        goto end;
    }

    if (pktb_transport_header(pkt_buff) == NULL) {
        char msg[300];
        if (type == IPV4) {
            syslog(LOG_WARNING, "Failed to set ipv4 transport header.");
            const __auto_type ip_hdr = nfq_ip_get_hdr(pkt_buff);
            if (ip_hdr != NULL) {
                nfq_ip_snprintf(msg, sizeof(msg), ip_hdr);
            } else {
                syslog(LOG_WARNING, "Failed to get ipv4 ip header");
                goto end;
            }
        } else {
            syslog(LOG_WARNING, "Failed to set ipv6 transport header.");
            const __auto_type ip_hdr = nfq_ip6_get_hdr(pkt_buff);
            if (ip_hdr != NULL) {
                nfq_ip6_snprintf(msg, sizeof(msg), ip_hdr);
            } else {
                syslog(LOG_WARNING, "Failed to get ipv6 ip header");
                goto end;
            }
        }
        syslog(LOG_WARNING, "Header: %s", msg);
        goto end;
    }

    const __auto_type tcp_hdr = nfq_tcp_get_hdr(pkt_buff);
    if (tcp_hdr == NULL) {
        // This packet is not tcp, pass it
        syslog(LOG_WARNING, "No tcp header found");
        io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NONE, NULL);
        goto end;
    }

    const __auto_type tcp_payload = nfq_tcp_get_payload(tcp_hdr, pkt_buff);
    if (tcp_payload == NULL) {
        // Empty ACK or no payload — just accept, don't mark
        io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NONE, NULL);
        goto end;
    }

    const __auto_type tcp_payload_len = nfq_tcp_get_payload_len(tcp_hdr, pkt_buff);
    if (tcp_payload_len == 0) {
        io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NONE, NULL);
        goto end;
    }

    count_tcp_packet();

    // Level 2: session lookup
    struct session_key skey;
    if (ct_ok) {
        skey = session_key_from_connid(pkt->conn_id);
    } else {
        // Build five-tuple from IP/TCP headers
        struct ip_tuple tuple;
        memset(&tuple, 0, sizeof(tuple));
        tuple.ip_version = type;
        if (type == IPV4) {
            const __auto_type ip_hdr = nfq_ip_get_hdr(pkt_buff);
            if (ip_hdr != NULL) {
                tuple.src.ip4 = ip_hdr->saddr;
                tuple.dst.ip4 = ip_hdr->daddr;
            }
        } else {
            const __auto_type ip_hdr = nfq_ip6_get_hdr(pkt_buff);
            if (ip_hdr != NULL) {
                memcpy(&tuple.src.in6, &ip_hdr->ip6_src, sizeof(struct in6_addr));
                memcpy(&tuple.dst.in6, &ip_hdr->ip6_dst, sizeof(struct in6_addr));
            }
        }
        tuple.src_port = ntohs(tcp_hdr->source);
        tuple.dst_port = ntohs(tcp_hdr->dest);
        skey = session_key_from_tuple(&tuple);
    }

    bool new_session = false;
    struct http_session *session = NULL;

    // Check if this looks like HTTP before creating session
    // (avoids session allocation for non-HTTP traffic)
    session_wrlock();
    session = session_find(&skey);

    if (session == NULL) {
        // No existing session — check if this looks like HTTP via fast path
        if (!is_http_protocol((const char *)tcp_payload, tcp_payload_len)) {
            session_wrunlock();
            // Not HTTP
            if (ct_ok) {
                add_to_cache(pkt);
                io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NOT_HTTP, NULL);
            } else {
                io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NONE, NULL);
            }
            goto end;
        }

        // Looks like HTTP — create session
        session = session_create(&skey);
        if (session == NULL) {
            session_wrunlock();
            syslog(LOG_WARNING, "Session limit reached, dropping packet");
            io->send_verdict(io_ctx, pkt, NF_DROP, MARK_NONE, NULL);
            goto end;
        }
        http_parser_init_session(session);
        new_session = true;
    }

    // Level 3: feed to llhttp (session is valid, we hold the lock)
    session_reset_per_packet(session, tcp_payload);
    const int parse_ret = http_parser_feed(session, (const char *)tcp_payload, tcp_payload_len);

    // Copy results out before releasing lock
    const int ua_count = session->ua_entry_count;
    struct ua_mangle_entry ua_entries_copy[UA_MAX_ENTRIES];
    if (ua_count > 0) {
        memcpy(ua_entries_copy, session->ua_entries, ua_count * sizeof(struct ua_mangle_entry));
    }

    if (parse_ret != 0) {
        session_delete(session);
        session_wrunlock();

        if (ct_ok) {
            add_to_cache(pkt);
            io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NOT_HTTP, NULL);
        } else {
            io->send_verdict(io_ctx, pkt, NF_ACCEPT, MARK_NONE, NULL);
        }
        goto end;
    }

    session_wrunlock();

    // Mangle UA entries (using copied data, session lock released)
    for (int i = 0; i < ua_count; i++) {
        const unsigned int ua_offset = ua_entries_copy[i].offset;
        const unsigned int ua_len = ua_entries_copy[i].len;

        if (type == IPV4) {
            if (!nfq_tcp_mangle_ipv4(pkt_buff, ua_offset, ua_len, replacement_user_agent_string, ua_len)) {
                syslog(LOG_ERR, "Failed to mangle ipv4 packet");
                goto end;
            }
        } else {
            if (!nfq_tcp_mangle_ipv6(pkt_buff, ua_offset, ua_len, replacement_user_agent_string, ua_len)) {
                syslog(LOG_ERR, "Failed to mangle ipv6 packet");
                goto end;
            }
        }
    }

    if (ua_count > 0) {
        count_user_agent_packet();
    }

    io->send_verdict(io_ctx, pkt, NF_ACCEPT,
                     (ct_ok && new_session) ? MARK_HTTP : MARK_NONE, pkt_buff);

end:
    free(pkt->payload);
    if (pkt_buff != NULL) {
        pktb_free(pkt_buff);
    }

    try_print_statistics();
}

#undef MAX_USER_AGENT_LENGTH
