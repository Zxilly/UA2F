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

int __build_conntrack(struct nfnl_subsys_handle *ssh,
		      struct nfnlhdr *req,
		      size_t size,
		      uint16_t type,
		      uint16_t flags,
		      const struct nf_conntrack *ct)
{
	uint8_t l3num = ct->head.orig.l3protonum;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;
	char *buf;

	if (!test_bit(ATTR_ORIG_L3PROTO, ct->head.set)) {
		errno = EINVAL;
		return -1;
	}

	memset(req, 0, size);

	buf = (char *)&req->nlh;
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | type;
	nlh->nlmsg_flags = flags;
	nlh->nlmsg_seq = 0;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = l3num;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nfct_nlmsg_build(nlh, ct);
}
