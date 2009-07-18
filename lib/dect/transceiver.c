/*
 * lib/dect/transceiver.c	DECT Transceiver objects
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

/**
 * @ingroup dect
 * @defgroup dect Transceivers
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/dect/transceiver.h>

/** @cond SKIP */
static struct nl_cache_ops nl_dect_transceiver_ops;
/** @endcond */

#define DECTNAMSIZ	16

static struct nla_policy transceiver_policy[DECTA_TRANSCEIVER_MAX + 1] = {
	[DECTA_TRANSCEIVER_NAME]	= { .type = NLA_STRING, .maxlen = DECTNAMSIZ },
	[DECTA_TRANSCEIVER_TYPE]	= { .type = NLA_STRING },
	[DECTA_TRANSCEIVER_LINK]	= { .type = NLA_U8 },
	[DECTA_TRANSCEIVER_STATS]	= { .type = NLA_NESTED },
	[DECTA_TRANSCEIVER_BAND]	= { .type = NLA_U8 },
	[DECTA_TRANSCEIVER_SLOTS]	= { .type = NLA_NESTED },
};

static struct nla_policy stats_policy[DECTA_TRANSCEIVER_STATS_MAX + 1] = {
	[DECTA_TRANSCEIVER_STATS_EVENT_BUSY]	= { .type = NLA_U32 },
	[DECTA_TRANSCEIVER_STATS_EVENT_LATE]	= { .type = NLA_U32 },
};

static struct nla_policy slot_policy[DECTA_SLOT_MAX + 1] = {
	[DECTA_SLOT_NUM]		= { .type = NLA_U8 },
	[DECTA_SLOT_STATE]		= { .type = NLA_U8 },
	[DECTA_SLOT_CARRIER]		= { .type = NLA_U8 },
	[DECTA_SLOT_FREQUENCY]		= { .type = NLA_U32 },
	[DECTA_SLOT_PHASEOFF]		= { .type = NLA_U32 },
	[DECTA_SLOT_RSSI]		= { .type = NLA_U8 },
	[DECTA_SLOT_RX_BYTES]		= { .type = NLA_U32 },
	[DECTA_SLOT_RX_PACKETS]		= { .type = NLA_U32 },
	[DECTA_SLOT_RX_A_CRC_ERRORS]	= { .type = NLA_U32 },
	[DECTA_SLOT_TX_BYTES]		= { .type = NLA_U32 },
	[DECTA_SLOT_TX_PACKETS]		= { .type = NLA_U32 },
};

static int slot_parser(struct nl_dect_transceiver *trx, struct nlattr *nla)
{
	struct nlattr *tb[DECTA_SLOT_MAX + 1];
	struct nl_dect_transceiver_slot *dts;
	uint8_t slot;
	int err;

	err = nla_parse_nested(tb, DECTA_SLOT_MAX, nla, slot_policy);
	if (err < 0)
		return err;

	if (tb[DECTA_SLOT_NUM] == NULL)
		return -NLE_INVAL;
	slot = nla_get_u8(tb[DECTA_SLOT_NUM]);
	dts = &trx->trx_slots[slot];

	dts->dts_valid = 1;
	if (tb[DECTA_SLOT_STATE] != NULL)
		dts->dts_state = nla_get_u8(tb[DECTA_SLOT_STATE]);
	if (tb[DECTA_SLOT_CARRIER] != NULL)
		dts->dts_carrier = nla_get_u8(tb[DECTA_SLOT_CARRIER]);
	if (tb[DECTA_SLOT_FREQUENCY] != NULL)
		dts->dts_frequency = nla_get_u32(tb[DECTA_SLOT_FREQUENCY]);
	if (tb[DECTA_SLOT_PHASEOFF] != NULL)
		dts->dts_phaseoff = nla_get_u32(tb[DECTA_SLOT_PHASEOFF]);
	if (tb[DECTA_SLOT_RSSI] != NULL)
		dts->dts_rssi = nla_get_u8(tb[DECTA_SLOT_RSSI]);
	if (tb[DECTA_SLOT_RX_BYTES] != NULL)
		dts->dts_rx_bytes = nla_get_u32(tb[DECTA_SLOT_RX_BYTES]);
	if (tb[DECTA_SLOT_RX_PACKETS] != NULL)
		dts->dts_rx_packets = nla_get_u32(tb[DECTA_SLOT_RX_PACKETS]);
	if (tb[DECTA_SLOT_RX_A_CRC_ERRORS] != NULL)
		dts->dts_rx_a_crc_errors = nla_get_u32(tb[DECTA_SLOT_RX_A_CRC_ERRORS]);
	if (tb[DECTA_SLOT_TX_BYTES] != NULL)
		dts->dts_tx_bytes = nla_get_u32(tb[DECTA_SLOT_TX_BYTES]);
	if (tb[DECTA_SLOT_TX_PACKETS] != NULL)
		dts->dts_tx_packets = nla_get_u32(tb[DECTA_SLOT_TX_PACKETS]);
	return 0;
}

static int stats_parser(struct nl_dect_transceiver *trx, struct nlattr *nla)
{
	struct nlattr *tb[DECTA_TRANSCEIVER_STATS_MAX + 1];
	struct nl_dect_transceiver_stats *stats = &trx->trx_stats;
	int err;

	err = nla_parse_nested(tb, DECTA_TRANSCEIVER_STATS_MAX, nla, stats_policy);
	if (err < 0)
		return err;

	if (tb[DECTA_TRANSCEIVER_STATS_EVENT_BUSY] != NULL)
		stats->trx_event_busy =
			nla_get_u32(tb[DECTA_TRANSCEIVER_STATS_EVENT_BUSY]);
	if (tb[DECTA_TRANSCEIVER_STATS_EVENT_LATE] != NULL)
		stats->trx_event_late =
			nla_get_u32(tb[DECTA_TRANSCEIVER_STATS_EVENT_LATE]);
	return 0;
}

static int transceiver_msg_parser(struct nl_cache_ops *ops,
				  struct sockaddr_nl *who,
				  struct nlmsghdr *n,
				  struct nl_parser_param *pp)
{
	struct nlattr *tb[DECTA_TRANSCEIVER_MAX + 1], *nla;
	struct nl_dect_transceiver *trx;
	int err;

	trx = nl_dect_transceiver_alloc();
	if (trx == NULL) {
		err = -NLE_NOMEM;
		goto errout;
	}

	trx->ce_msgtype = n->nlmsg_type;

	err = nlmsg_parse(n, sizeof(struct dectmsg), tb, DECTA_TRANSCEIVER_MAX,
			  transceiver_policy);
	if (err < 0)
		goto errout;

	if (tb[DECTA_TRANSCEIVER_NAME] != NULL) {
		char name[DECTNAMSIZ];
		nla_strlcpy(name, tb[DECTA_TRANSCEIVER_NAME], sizeof(name));
		nl_dect_transceiver_set_name(trx, name);
	}

	if (tb[DECTA_TRANSCEIVER_TYPE] != NULL) {
		char *type = nla_strdup(tb[DECTA_TRANSCEIVER_TYPE]);
		if (type == NULL) {
			err = -NLE_NOMEM;
			goto errout;
		}
		nl_dect_transceiver_set_type(trx, type);
		free(type);
	}

	if (tb[DECTA_TRANSCEIVER_LINK] != NULL)
		nl_dect_transceiver_set_link(trx, nla_get_u8(tb[DECTA_TRANSCEIVER_LINK]));

	if (tb[DECTA_TRANSCEIVER_STATS] != NULL) {
		err = stats_parser(trx, tb[DECTA_TRANSCEIVER_STATS]);
		if (err < 0)
			goto errout;
	}

	if (tb[DECTA_TRANSCEIVER_BAND] != NULL)
		nl_dect_transceiver_set_band(trx, nla_get_u8(tb[DECTA_TRANSCEIVER_BAND]));

	if (tb[DECTA_TRANSCEIVER_SLOTS] != NULL) {
		int rem;
		nla_for_each_nested(nla, tb[DECTA_TRANSCEIVER_SLOTS], rem) {
			if (nla_type(nla) != DECTA_LIST_ELEM)
				continue;
			err = slot_parser(trx, nla);
			if (err < 0)
				goto errout;
		}
	}

	err = pp->pp_cb((struct nl_object *)trx, pp);
errout:
	nl_dect_transceiver_put(trx);
	return err;
}

static int transceiver_request_update(struct nl_cache *c, struct nl_sock *h)
{
	struct dectmsg dm;

	memset(&dm, 0, sizeof(dm));
	return nl_send_simple(h, DECT_GET_TRANSCEIVER, NLM_F_DUMP,
			      &dm, sizeof(dm));
}

/**
 * @name Cache Management
 * @{
 */
int nl_dect_transceiver_alloc_cache(struct nl_sock *sk, struct nl_cache **result)
{
	struct nl_cache *cache;
	int err;

	cache = nl_cache_alloc(&nl_dect_transceiver_ops);
	if (cache == NULL)
		return -NLE_NOMEM;

	if (sk && (err = nl_cache_refill(sk, cache)) < 0) {
		free(cache);
		return err;
	}

	*result = cache;
	return 0;
}

/** @} */

/**
 * @name Transceiver creation
 * @{
 */

static int build_transceiver_msg(struct nl_dect_transceiver *tmpl, int cmd,
				 int flags, struct nl_msg **result)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (msg == NULL)
		return -NLE_NOMEM;

	err = nl_dect_transceiver_build_msg(msg, tmpl);
	if (err < 0) {
		nlmsg_free(msg);
		return err;
	}

	*result = msg;
	return 0;
}

int nl_dect_transceiver_build_change_request(struct nl_dect_transceiver *tmpl,
					     int flags, struct nl_msg **result)
{
	return build_transceiver_msg(tmpl, DECT_NEW_TRANSCEIVER, flags, result);
}

int nl_dect_transceiver_change(struct nl_sock *sk, struct nl_dect_transceiver *trx,
			    int flags)
{
	struct nl_msg *msg;
	int err;

	err = nl_dect_transceiver_build_change_request(trx, flags, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

static struct nl_cache_ops nl_dect_transceiver_ops = {
	.co_name		= "nl_dect/transceiver",
	.co_hdrsize		= 0,
	.co_msgtypes		= {
		{ DECT_NEW_TRANSCEIVER, NL_ACT_NEW, "new" },
		{ DECT_GET_TRANSCEIVER, NL_ACT_GET, "get" },
		END_OF_MSGTYPES_LIST
	},
	.co_protocol		= NETLINK_DECT,
	.co_request_update	= transceiver_request_update,
	.co_msg_parser		= transceiver_msg_parser,
	.co_obj_ops		= &nl_dect_transceiver_obj_ops,
};

static void __init transceiver_init(void)
{
	nl_cache_mngt_register(&nl_dect_transceiver_ops);
}

static void __exit transceiver_exit(void)
{
	nl_cache_mngt_unregister(&nl_dect_transceiver_ops);
}

/** @} */
