/*
 * lib/nl_dect/cell.c		DECT Cell objects
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

/**
 * @ingroup nl_dect
 * @defgroup nl_dect Transceivers
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/dect/cell.h>
#include <netlink/dect/ari.h>
#include <linux/dect_netlink.h>

/** @cond SKIP */
static struct nl_cache_ops nl_dect_cell_ops;
/** @endcond */

static struct nla_policy cell_policy[DECTA_CELL_MAX + 1] = {
	[DECTA_CELL_NAME]		= { .type = NLA_STRING, .maxlen = 16 },
	[DECTA_CELL_FLAGS]		= { .type = NLA_U32 },
	[DECTA_CELL_TRANSCEIVERS]	= { .type = NLA_NESTED },
	[DECTA_CELL_CLUSTER]		= { .type = NLA_U8 },
};

static int cell_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			   struct nlmsghdr *n, struct nl_parser_param *pp)
{
	struct dectmsg *dm = nlmsg_data(n);
	struct nl_dect_cell *cell;
	struct nlattr *tb[DECTA_CELL_MAX + 1], *nla;
	int rem, err;

	err = nlmsg_parse(n, sizeof(*dm), tb, DECTA_CELL_MAX, cell_policy);
	if (err < 0)
		return err;

	cell = nl_dect_cell_alloc();
	if (cell == NULL) {
		err = -NLE_NOMEM;
		goto errout;
	}

	cell->ce_msgtype = n->nlmsg_type;
	cell->c_index = dm->dm_index;

	if (tb[DECTA_CELL_NAME] != NULL)
		nl_dect_cell_set_name(cell, nla_data(tb[DECTA_CELL_NAME]));
	if (tb[DECTA_CELL_FLAGS] != NULL)
		nl_dect_cell_set_flags(cell, nla_get_u32(tb[DECTA_CELL_FLAGS]));
	if (tb[DECTA_CELL_TRANSCEIVERS] != NULL) {
		unsigned int i = 0;
		nla_for_each_nested(nla, tb[DECTA_CELL_TRANSCEIVERS], rem) {
			char *id = nla_strdup(nla);
			if (id == NULL) {
				err = -NLE_NOMEM;
				goto errout;
			}
			nl_dect_cell_set_transceiver(cell, i++, id);
		}
	}
	if (tb[DECTA_CELL_CLUSTER] != NULL)
		nl_dect_cell_set_link(cell, nla_get_u8(tb[DECTA_CELL_CLUSTER]));

	err = pp->pp_cb((struct nl_object *)cell, pp);
errout:
	nl_dect_cell_put(cell);
	return err;
}

static int cell_request_update(struct nl_cache *c, struct nl_sock *h)
{
	struct dectmsg dm;

	memset(&dm, 0, sizeof(dm));
	return nl_send_simple(h, DECT_GET_CELL, NLM_F_DUMP, &dm, sizeof(dm));
}

/**
 * @name Cache Management
 * @{
 */
int nl_dect_cell_alloc_cache(struct nl_sock *sk, struct nl_cache **result)
{
	struct nl_cache *cache;
	int err;

	cache = nl_cache_alloc(&nl_dect_cell_ops);
	if (cache == NULL)
		return -NLE_NOMEM;

	if (sk && (err = nl_cache_refill(sk, cache)) < 0) {
		free(cache);
		return err;
	}

	*result = cache;
	return 0;
}

struct nl_dect_cell *nl_dect_cell_get_by_name(struct nl_cache *cache, const char *name)
{
	struct nl_dect_cell *cell;

	nl_list_for_each_entry(cell, &cache->c_items, ce_list) {
		if (!strcmp(cell->c_name, name)) {
			nl_object_get((struct nl_object *)cell);
			return cell;
		}
	}
	return NULL;
}

struct nl_dect_cell *nl_dect_cell_get_by_index(struct nl_cache *cache, int index)
{
	struct nl_dect_cell *cell;

	nl_list_for_each_entry(cell, &cache->c_items, ce_list) {
		if (cell->c_index == index) {
			nl_object_get((struct nl_object *)cell);
			return cell;
		}
	}
	return NULL;
}

/** @} */

/**
 * @name Device creation
 * @{
 */

static int build_cell_msg(struct nl_dect_cell *tmpl, int cmd, int flags,
			  struct nl_msg **result)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (msg == NULL)
		return -NLE_NOMEM;

	err = nl_dect_cell_build_msg(msg, tmpl);
	if (err < 0) {
		nlmsg_free(msg);
		return err;
	}

	*result = msg;
	return 0;
}

int nl_dect_cell_build_add_request(struct nl_dect_cell *tmpl, int flags,
				   struct nl_msg **result)
{
	return build_cell_msg(tmpl, DECT_NEW_CELL, NLM_F_CREATE | flags,
			      result);
}

int nl_dect_cell_add(struct nl_sock *sk, struct nl_dect_cell *cell, int flags)
{
	struct nl_msg *msg;
	int err;

	err = nl_dect_cell_build_add_request(cell, flags, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

int nl_dect_cell_build_del_request(struct nl_dect_cell *tmpl, int flags,
				   struct nl_msg **result)
{
	return build_cell_msg(tmpl, DECT_DEL_CELL, flags, result);
}

int nl_dect_cell_delete(struct nl_sock *sk, struct nl_dect_cell *tmpl, int flags)
{
	struct nl_msg *msg;
	int err;

	err = nl_dect_cell_build_del_request(tmpl, flags, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

/** @} */

/**
 * @name Name <-> Index Translations
 * @{
 */

char *nl_dect_cell_i2name(struct nl_cache *cache, int index, char *buf, size_t len)
{
	struct nl_dect_cell *cell = nl_dect_cell_get_by_index(cache, index);

	if (cell != NULL) {
		strncpy(buf, cell->c_name, len - 1);
		buf[len - 1] = 0;
		return buf;
	}
	return NULL;
}

int nl_dect_cell_name2i(struct nl_cache *cache, const char *name)
{
	struct nl_dect_cell *cell = nl_dect_cell_get_by_name(cache, name);

	if (cell != NULL)
		return cell->c_index;
	return 0;
}

/** @} */

static struct nl_cache_ops nl_dect_cell_ops = {
	.co_name		= "nl_dect/cell",
	.co_hdrsize		= 0,
	.co_msgtypes		= {
		{ DECT_NEW_CELL, NL_ACT_NEW, "new" },
		{ DECT_DEL_CELL, NL_ACT_NEW, "del" },
		{ DECT_GET_CELL, NL_ACT_GET, "get" },
		END_OF_MSGTYPES_LIST
	},
	.co_protocol		= NETLINK_DECT,
	.co_request_update	= cell_request_update,
	.co_msg_parser		= cell_msg_parser,
	.co_obj_ops		= &nl_dect_cell_obj_ops,
};

static void __init cell_init(void)
{
	nl_cache_mngt_register(&nl_dect_cell_ops);
}

static void __exit cell_exit(void)
{
	nl_cache_mngt_unregister(&nl_dect_cell_ops);
}

/** @} */
