/*
 * lib/dect/cluster.c		DECT Cluster objects
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
#include <netlink/dect/cluster.h>
#include <netlink/dect/ari.h>
#include <linux/dect_netlink.h>

/** @cond SKIP */
static struct nl_cache_ops nl_dect_cluster_ops;
/** @endcond */

static struct nla_policy mbc_tb_policy[DECTA_MBC_TB_MAX + 1] = {
	[DECTA_MBC_TB_LBN]		= { .type = NLA_U8 },
	[DECTA_MBC_TB_ECN]		= { .type = NLA_U8 },
	[DECTA_MBC_TB_CELL]		= { .type = NLA_U8 },
	[DECTA_MBC_TB_RX_SLOT]		= { .type = NLA_U8 },
	[DECTA_MBC_TB_TX_SLOT]		= { .type = NLA_U8 },
};

static int tb_msg_parser(struct nlattr *nla, struct nl_dect_mbc *mbc)
{
	struct nlattr *tb[DECTA_MBC_TB_MAX + 1];
	struct nl_dect_mbc_tb *mtb;
	int err;

	if (nla_type(nla) != DECTA_LIST_ELEM)
		return -NLE_INVAL;

	err = nla_parse_nested(tb, DECTA_MBC_TB_MAX, nla, mbc_tb_policy);
	if (err < 0)
		return err;

	mtb = &mbc->mbc_tbs[mbc->mbc_ntbs++];
	if (tb[DECTA_MBC_TB_LBN] != NULL)
		mtb->mtb_lbn = nla_get_u8(tb[DECTA_MBC_TB_LBN]);
	if (tb[DECTA_MBC_TB_ECN] != NULL)
		mtb->mtb_ecn = nla_get_u8(tb[DECTA_MBC_TB_ECN]);
	if (tb[DECTA_MBC_TB_CELL] != NULL)
		mtb->mtb_cell = nla_get_u8(tb[DECTA_MBC_TB_CELL]);
	if (tb[DECTA_MBC_TB_RX_SLOT] != NULL)
		mtb->mtb_rx_slot = nla_get_u8(tb[DECTA_MBC_TB_RX_SLOT]);
	if (tb[DECTA_MBC_TB_TX_SLOT] != NULL)
		mtb->mtb_tx_slot = nla_get_u8(tb[DECTA_MBC_TB_TX_SLOT]);

	return 0;
}

static struct nla_policy mbc_stats_policy[DECTA_MBC_STATS_MAX + 1] = {
	[DECTA_MBC_STATS_CS_RX_BYTES]	= { .type = NLA_U32 },
	[DECTA_MBC_STATS_CS_TX_BYTES]	= { .type = NLA_U32 },
	[DECTA_MBC_STATS_I_RX_BYTES]	= { .type = NLA_U32 },
	[DECTA_MBC_STATS_I_TX_BYTES]	= { .type = NLA_U32 },
	[DECTA_MBC_STATS_HANDOVERS]	= { .type = NLA_U32 },
};

static int mbc_stats_msg_parser(struct nlattr *nla, struct nl_dect_mbc *mbc)
{
	struct nlattr *tb[DECTA_MBC_STATS_MAX + 1];
	int err;

	err = nla_parse_nested(tb, DECTA_MBC_MAX, nla, mbc_stats_policy);
	if (err < 0)
		return err;

	if (tb[DECTA_MBC_STATS_CS_RX_BYTES] != NULL)
		mbc->mbc_cs_rx_bytes = nla_get_u32(tb[DECTA_MBC_STATS_CS_RX_BYTES]);
	if (tb[DECTA_MBC_STATS_CS_TX_BYTES] != NULL)
		mbc->mbc_cs_tx_bytes = nla_get_u32(tb[DECTA_MBC_STATS_CS_TX_BYTES]);
	if (tb[DECTA_MBC_STATS_I_RX_BYTES] != NULL)
		mbc->mbc_i_rx_bytes = nla_get_u32(tb[DECTA_MBC_STATS_I_RX_BYTES]);
	if (tb[DECTA_MBC_STATS_I_TX_BYTES] != NULL)
		mbc->mbc_i_tx_bytes = nla_get_u32(tb[DECTA_MBC_STATS_I_TX_BYTES]);
	if (tb[DECTA_MBC_STATS_HANDOVERS] != NULL)
		mbc->mbc_handovers = nla_get_u32(tb[DECTA_MBC_STATS_HANDOVERS]);
	return 0;
}

static struct nla_policy mbc_policy[DECTA_MBC_MAX + 1] = {
	[DECTA_MBC_MCEI]		= { .type = NLA_U32 },
	[DECTA_MBC_SERVICE]		= { .type = NLA_U8 },
	[DECTA_MBC_STATE]		= { .type = NLA_U8 },
	[DECTA_MBC_CIPHER_STATE]	= { .type = NLA_U8 },
	[DECTA_MBC_TBS]			= { .type = NLA_NESTED },
};

static int mbc_msg_parser(struct nlattr *nla, struct nl_dect_cluster *cl)
{
	struct nlattr *tb[DECTA_MBC_MAX + 1];
	struct nl_dect_mbc *mbc;
	int err, rem;

	if (nla_type(nla) != DECTA_LIST_ELEM)
		return -NLE_INVAL;

	err = nla_parse_nested(tb, DECTA_MBC_MAX, nla, mbc_policy);
	if (err < 0)
		return err;

	mbc = &cl->cl_mbcs[cl->cl_nmbcs++];
	if (tb[DECTA_MBC_MCEI] != NULL)
		mbc->mbc_mcei = nla_get_u32(tb[DECTA_MBC_MCEI]);
	if (tb[DECTA_MBC_SERVICE] != NULL)
		mbc->mbc_service = nla_get_u8(tb[DECTA_MBC_SERVICE]);
	if (tb[DECTA_MBC_STATE] != NULL)
		mbc->mbc_state = nla_get_u8(tb[DECTA_MBC_STATE]);
	if (tb[DECTA_MBC_CIPHER_STATE] != NULL)
		mbc->mbc_cipher_state = nla_get_u8(tb[DECTA_MBC_CIPHER_STATE]);
	if (tb[DECTA_MBC_STATS] != NULL) {
		err = mbc_stats_msg_parser(tb[DECTA_MBC_STATS], mbc);
		if (err < 0)
			return err;
	}
	if (tb[DECTA_MBC_TBS] != NULL) {
		nla_for_each_nested(nla, tb[DECTA_MBC_TBS], rem) {
			err = tb_msg_parser(nla, mbc);
			if (err < 0)
				return err;
		}
	}
	return 0;
}

static struct nla_policy cluster_policy[DECTA_CLUSTER_MAX + 1] = {
	[DECTA_CLUSTER_NAME]		= { .type = NLA_STRING, .maxlen = 16 },
	[DECTA_CLUSTER_MODE]		= { .type = NLA_U8 },
	[DECTA_CLUSTER_PARI]		= { .type = NLA_NESTED },
	[DECTA_CLUSTER_CELLS]		= { .type = NLA_NESTED },
	[DECTA_CLUSTER_MBCS]		= { .type = NLA_NESTED },
};

static int cluster_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			      struct nlmsghdr *n, struct nl_parser_param *pp)
{
	struct dectmsg *dm = nlmsg_data(n);
	struct nl_dect_cluster *cl;
	struct nlattr *tb[DECTA_CLUSTER_MAX + 1], *nla;
	int err, rem;

	err = nlmsg_parse(n, sizeof(*dm), tb, DECTA_CLUSTER_MAX, cluster_policy);
	if (err < 0)
		return err;

	cl = nl_dect_cluster_alloc();
	if (cl == NULL) {
		err = -NLE_NOMEM;
		goto errout;
	}

	cl->ce_msgtype = n->nlmsg_type;
	cl->cl_index = dm->dm_index;

	if (tb[DECTA_CLUSTER_NAME] != NULL) {
		char *name = nla_strdup(tb[DECTA_CLUSTER_NAME]);
		if (name == NULL) {
			err = -NLE_NOMEM;
			goto errout;
		}
		nl_dect_cluster_set_name(cl, name);
		free(name);
	}

	if (tb[DECTA_CLUSTER_MODE] != NULL)
		nl_dect_cluster_set_mode(cl, nla_get_u8(tb[DECTA_CLUSTER_MODE]));

	if (tb[DECTA_CLUSTER_PARI] != NULL) {
		struct nl_dect_ari pari;

		err = nl_dect_parse_ari(&pari, tb[DECTA_CLUSTER_PARI]);
		if (err < 0)
			goto errout;
		nl_dect_cluster_set_pari(cl, &pari);
	}

	if (tb[DECTA_CLUSTER_MBCS] != NULL) {
		nla_for_each_nested(nla, tb[DECTA_CLUSTER_MBCS], rem) {
			err = mbc_msg_parser(nla, cl);
			if (err < 0)
				goto errout;
		}
	}

	err = pp->pp_cb((struct nl_object *)cl, pp);
errout:
	nl_dect_cluster_put(cl);
	return err;
}

static int cluster_request_update(struct nl_cache *c, struct nl_sock *h)
{
	struct dectmsg dm;

	memset(&dm, 0, sizeof(dm));
	return nl_send_simple(h, DECT_GET_CLUSTER, NLM_F_DUMP, &dm, sizeof(dm));
}

/**
 * @name Cache Management
 * @{
 */
int nl_dect_cluster_alloc_cache(struct nl_sock *sk, struct nl_cache **result)
{
	struct nl_cache *cache;
	int err;

	cache = nl_cache_alloc(&nl_dect_cluster_ops);
	if (cache == NULL)
		return -NLE_NOMEM;

	if (sk && (err = nl_cache_refill(sk, cache)) < 0) {
		free(cache);
		return err;
	}

	*result = cache;
	return 0;
}

struct nl_dect_cluster *nl_dect_cluster_get_by_name(struct nl_cache *cache,
						    const char *name)
{
	struct nl_dect_cluster *cl;

	nl_list_for_each_entry(cl, &cache->c_items, ce_list) {
		if (!strcmp(cl->cl_name, name)) {
			nl_object_get((struct nl_object *)cl);
			return cl;
		}
	}
	return NULL;
}

struct nl_dect_cluster *nl_dect_cluster_get_by_index(struct nl_cache *cache, int index)
{
	struct nl_dect_cluster *cl;

	nl_list_for_each_entry(cl, &cache->c_items, ce_list) {
		if (cl->cl_index == index) {
			nl_object_get((struct nl_object *)cl);
			return cl;
		}
	}
	return NULL;
}

/** @} */

/**
 * @name Device creation
 * @{
 */

static int build_cluster_msg(struct nl_dect_cluster *tmpl, int cmd, int flags,
			     struct nl_msg **result)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (msg == NULL)
		return -NLE_NOMEM;

	err = nl_dect_cluster_build_msg(msg, tmpl);
	if (err < 0) {
		nlmsg_free(msg);
		return err;
	}

	*result = msg;
	return 0;
}

int nl_dect_cluster_build_add_request(struct nl_dect_cluster *tmpl, int flags,
				      struct nl_msg **result)
{
	return build_cluster_msg(tmpl, DECT_NEW_CLUSTER, NLM_F_CREATE | flags,
			        result);
}

int nl_dect_cluster_add(struct nl_sock *sk, struct nl_dect_cluster *cl, int flags)
{
	struct nl_msg *msg;
	int err;

	err = nl_dect_cluster_build_add_request(cl, flags, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

int nl_dect_cluster_build_del_request(struct nl_dect_cluster *tmpl, int flags,
				      struct nl_msg **result)
{
	return build_cluster_msg(tmpl, DECT_DEL_CLUSTER, flags, result);
}

int nl_dect_cluster_delete(struct nl_sock *sk, struct nl_dect_cluster *tmpl, int flags)
{
	struct nl_msg *msg;
	int err;

	err = nl_dect_cluster_build_del_request(tmpl, flags, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

int nl_dect_cluster_build_query_request(struct nl_dect_cluster *tmpl, int flags,
					struct nl_msg **result)
{
	return build_cluster_msg(tmpl, DECT_GET_CLUSTER, flags, result);
}

int nl_dect_cluster_query(struct nl_sock *sk, struct nl_dect_cluster *cl, int flags)
{
	struct nl_msg *msg;
	int err;

	err = nl_dect_cluster_build_query_request(cl, flags, &msg);
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

char *nl_dect_cluster_i2name(struct nl_cache *cache, int index,
			     char *buf, size_t len)
{
	struct nl_dect_cluster *cl = nl_dect_cluster_get_by_index(cache, index);

	if (cl != NULL) {
		strncpy(buf, cl->cl_name, len - 1);
		buf[len - 1] = 0;
		return buf;
	}

	return NULL;
}

int nl_dect_cluster_name2i(struct nl_cache *cache, const char *name)
{
	struct nl_dect_cluster *cl = nl_dect_cluster_get_by_name(cache, name);

	if (cl != NULL)
		return cl->cl_index;
	return 0;
}

/** @} */

static struct nl_cache_ops nl_dect_cluster_ops = {
	.co_name		= "nl_dect/cluster",
	.co_hdrsize		= 0,
	.co_msgtypes		= {
		{ DECT_NEW_CLUSTER, NL_ACT_NEW, "new" },
		{ DECT_DEL_CLUSTER, NL_ACT_NEW, "del" },
		{ DECT_GET_CLUSTER, NL_ACT_GET, "get" },
		END_OF_MSGTYPES_LIST
	},
	.co_protocol		= NETLINK_DECT,
	.co_request_update	= cluster_request_update,
	.co_msg_parser		= cluster_msg_parser,
	.co_obj_ops		= &nl_dect_cluster_obj_ops,
};

static void __init cluster_init(void)
{
	nl_cache_mngt_register(&nl_dect_cluster_ops);
}

static void __exit cluster_exit(void)
{
	nl_cache_mngt_unregister(&nl_dect_cluster_ops);
}

/** @} */
