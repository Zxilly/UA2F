/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "internal/internal.h"

static void set_exp_attr_master(struct nf_expect *exp, const void *value)
{
	exp->master = *((struct nfct_tuple_head *) value);
}

static void set_exp_attr_expected(struct nf_expect *exp, const void *value)
{
	exp->expected = *((struct nfct_tuple_head *) value);
}

static void set_exp_attr_mask(struct nf_expect *exp, const void *value)
{
	exp->mask = *((struct nfct_tuple_head *) value);
}

static void set_exp_attr_timeout(struct nf_expect *exp, const void *value)
{
	exp->timeout = *((uint32_t *) value);
}

static void set_exp_attr_zone(struct nf_expect *exp, const void *value)
{
	exp->zone = *((uint16_t *) value);
}

static void set_exp_attr_flags(struct nf_expect *exp, const void *value)
{
	exp->flags = *((uint32_t *) value);
}

static void set_exp_attr_class(struct nf_expect *exp, const void *value)
{
	exp->class = *((uint32_t *) value);
}

static void set_exp_attr_helper_name(struct nf_expect *exp, const void *value)
{
	snprintf(exp->helper_name, NFCT_HELPER_NAME_MAX, "%s", (char *)value);
}

static void set_exp_attr_nat_dir(struct nf_expect *exp, const void *value)
{
	exp->nat_dir = *((uint32_t *) value);
}

static void set_exp_attr_nat_tuple(struct nf_expect *exp, const void *value)
{
	exp->nat = *((struct nfct_tuple_head *) value);
}

static void set_exp_attr_expectfn(struct nf_expect *exp, const void *value)
{
	snprintf(exp->expectfn, __NFCT_EXPECTFN_MAX, "%s", (char *)value);
}

const set_exp_attr set_exp_attr_array[ATTR_EXP_MAX] = {
	[ATTR_EXP_MASTER]		= set_exp_attr_master,
	[ATTR_EXP_EXPECTED]		= set_exp_attr_expected,
	[ATTR_EXP_MASK]			= set_exp_attr_mask,
	[ATTR_EXP_TIMEOUT]		= set_exp_attr_timeout,
	[ATTR_EXP_ZONE]			= set_exp_attr_zone,
	[ATTR_EXP_FLAGS]		= set_exp_attr_flags,
	[ATTR_EXP_HELPER_NAME]		= set_exp_attr_helper_name,
	[ATTR_EXP_CLASS]		= set_exp_attr_class,
	[ATTR_EXP_NAT_TUPLE]		= set_exp_attr_nat_tuple,
	[ATTR_EXP_NAT_DIR]		= set_exp_attr_nat_dir,
	[ATTR_EXP_FN]			= set_exp_attr_expectfn,
};
