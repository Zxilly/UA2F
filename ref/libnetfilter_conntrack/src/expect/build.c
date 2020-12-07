/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal/internal.h"
#include <libmnl/libmnl.h>

int __build_expect(struct nfnl_subsys_handle *ssh,
		   struct nfnlhdr *req,
		   size_t size,
		   uint16_t type,
		   uint16_t flags,
		   const struct nf_expect *exp)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;
	uint8_t l3num;
	char *buf;

	if (test_bit(ATTR_ORIG_L3PROTO, exp->master.set))
		l3num = exp->master.orig.l3protonum;
	else if (test_bit(ATTR_ORIG_L3PROTO, exp->expected.set))
		l3num = exp->expected.orig.l3protonum;
	else
		return -1;

	memset(req, 0, size);

	buf = (char *)&req->nlh;
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK_EXP << 8) | type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = 0;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = l3num;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nfexp_nlmsg_build(nlh, exp);
}
