/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal/internal.h"

static void set_attr_grp_orig_ipv4(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv4 *this = value;
	ct->head.orig.src.v4 = this->src;
	ct->head.orig.dst.v4 = this->dst;
	ct->head.orig.l3protonum = AF_INET;
}

static void set_attr_grp_repl_ipv4(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv4 *this = value;
	ct->repl.src.v4 = this->src;
	ct->repl.dst.v4 = this->dst;
	ct->repl.l3protonum = AF_INET;
}

static void set_attr_grp_orig_ipv6(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv6 *this = value;
	memcpy(&ct->head.orig.src.v6, this->src, sizeof(uint32_t)*4);
	memcpy(&ct->head.orig.dst.v6, this->dst, sizeof(uint32_t)*4);
	ct->head.orig.l3protonum = AF_INET6;
}

static void set_attr_grp_repl_ipv6(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv6 *this = value;
	memcpy(&ct->repl.src.v6, this->src, sizeof(uint32_t)*4);
	memcpy(&ct->repl.dst.v6, this->dst, sizeof(uint32_t)*4);
	ct->repl.l3protonum = AF_INET6;
}

static void set_attr_grp_orig_port(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_port *this = value;
	ct->head.orig.l4src.all = this->sport;
	ct->head.orig.l4dst.all = this->dport;
}

static void set_attr_grp_repl_port(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_port *this = value;
	ct->repl.l4src.all = this->sport;
	ct->repl.l4dst.all = this->dport;
}

static void set_attr_grp_icmp(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_icmp *this = value;
	uint8_t rtype = 0;

	ct->head.orig.l4dst.icmp.type = this->type;

	switch(ct->head.orig.l3protonum) {
		case AF_INET:
			rtype = __icmp_reply_type(this->type);
			break;

		case AF_INET6:
			rtype = __icmpv6_reply_type(this->type);
			break;

		default:
			rtype = 0;	/* not found */
	}

	if (rtype)
		ct->repl.l4dst.icmp.type = rtype - 1;
	else
		ct->repl.l4dst.icmp.type = 255;	/* -EINVAL */

	ct->head.orig.l4dst.icmp.code = this->code;
	ct->repl.l4dst.icmp.code = this->code;

	ct->head.orig.l4src.icmp.id = this->id;
	ct->repl.l4src.icmp.id = this->id;
}

static void set_attr_grp_master_ipv4(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv4 *this = value;
	ct->master.src.v4 = this->src;
	ct->master.dst.v4 = this->dst;
	ct->master.l3protonum = AF_INET;
}

static void set_attr_grp_master_ipv6(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_ipv6 *this = value;
	memcpy(&ct->master.src.v6, this->src, sizeof(uint32_t)*4);
	memcpy(&ct->master.dst.v6, this->dst, sizeof(uint32_t)*4);
	ct->master.l3protonum = AF_INET6;
}

static void set_attr_grp_master_port(struct nf_conntrack *ct, const void *value)
{
	const struct nfct_attr_grp_port *this = value;
	ct->master.l4src.all = this->sport;
	ct->master.l4dst.all = this->dport;
}

static void set_attr_grp_do_nothing(struct nf_conntrack *ct, const void *value)
{
}

const set_attr_grp set_attr_grp_array[ATTR_GRP_MAX] = {
	[ATTR_GRP_ORIG_IPV4]		= set_attr_grp_orig_ipv4,
	[ATTR_GRP_REPL_IPV4]		= set_attr_grp_repl_ipv4,
	[ATTR_GRP_ORIG_IPV6]		= set_attr_grp_orig_ipv6,
	[ATTR_GRP_REPL_IPV6]		= set_attr_grp_repl_ipv6,
	[ATTR_GRP_ORIG_PORT]		= set_attr_grp_orig_port,
	[ATTR_GRP_REPL_PORT]		= set_attr_grp_repl_port,
	[ATTR_GRP_ICMP]			= set_attr_grp_icmp,
	[ATTR_GRP_MASTER_IPV4]		= set_attr_grp_master_ipv4,
	[ATTR_GRP_MASTER_IPV6]		= set_attr_grp_master_ipv6,
	[ATTR_GRP_MASTER_PORT]		= set_attr_grp_master_port,
	[ATTR_GRP_ORIG_COUNTERS]	= set_attr_grp_do_nothing,
	[ATTR_GRP_REPL_COUNTERS]	= set_attr_grp_do_nothing,
	[ATTR_GRP_ORIG_ADDR_SRC]	= set_attr_grp_do_nothing,
	[ATTR_GRP_ORIG_ADDR_DST]	= set_attr_grp_do_nothing,
	[ATTR_GRP_REPL_ADDR_SRC]	= set_attr_grp_do_nothing,
	[ATTR_GRP_REPL_ADDR_DST]	= set_attr_grp_do_nothing,
};
