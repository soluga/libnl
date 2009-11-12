/*
 * lib/dect/transceiver_obj.c	DECT Transceiver objects
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/data.h>
#include <netlink/dect/dect.h>
#include <netlink/dect/cell.h>
#include <netlink/dect/transceiver.h>

/** @cond SKIP */
#define TRANSCEIVER_ATTR_NAME		0x0001
#define TRANSCEIVER_ATTR_TYPE		0x0002
#define TRANSCEIVER_ATTR_INDEX		0x0004
#define TRANSCEIVER_ATTR_LINK		0x0008
#define TRANSCEIVER_ATTR_BAND		0x0010
/** @endtsond */

static void transceiver_free_data(struct nl_object *obj)
{
	struct nl_dect_transceiver *trx = nl_object_priv(obj);

	if (trx == NULL)
		return;
	free(trx->trx_name);
	free(trx->trx_type);
}

static void slot_dump(struct nl_dect_transceiver_slot *dts, unsigned int n,
		      struct nl_dump_params *p)
{
	int64_t offset;
	char buf[64];

	nl_dect_slot_state2str(dts->dts_state, buf, sizeof(buf));
	nl_dump(p, "\tslot %u: <%s> ", n, buf);
	nl_dump(p, "carrier: %u (%u.%03u MHz", dts->dts_carrier,
		dts->dts_frequency / 1000, dts->dts_frequency % 1000);

	if (dts->dts_state == DECT_SLOT_RX) {
		offset = (int64_t)dts->dts_frequency * dts->dts_phaseoff /
			 DECT_PHASE_OFFSET_SCALE;
		nl_dump(p, " %+" PRId64 ".%03" PRIu64 " kHz",
			offset / 1000000, llabs(offset) % 1000000 / 1000);
	}
	nl_dump(p, ")");

	if (dts->dts_state == DECT_SLOT_RX)
		nl_dump(p, " signal level: %.2fdBm",
			nl_dect_rssi_to_dbm(dts->dts_rssi));
	nl_dump(p, "\n");

	nl_dump(p, "\t    RX: bytes %u packets %u crc-errors %u\n",
		dts->dts_rx_bytes, dts->dts_rx_packets, dts->dts_rx_a_crc_errors);
	nl_dump(p, "\t    TX: bytes %u packets %u\n",
		dts->dts_tx_bytes, dts->dts_tx_packets);
}

static void transceiver_dump(struct nl_object *obj, struct nl_dump_params *p)
{
	struct nl_dect_transceiver *trx = nl_object_priv(obj);
	struct nl_dect_transceiver_stats *stats = &trx->trx_stats;
	struct nl_dect_transceiver_slot *dts;
	struct nl_cache *cell_cache;
	char buf[64];
	unsigned int n;

	nl_dump(p, "DECT Transceiver ");
	if (trx->trx_name != NULL)
		nl_dump_line(p, "%s", trx->trx_name);

	if (trx->trx_link) {
		cell_cache = nl_cache_mngt_require("nl_dect/cell");
		if (cell_cache != NULL) {
			nl_dump(p, "@%s",
				nl_dect_cell_i2name(cell_cache, trx->trx_link,
						 buf, sizeof(buf)));
		} else
			nl_dump(p, "@%d", trx->trx_link);
	}
	nl_dump(p, ":\n");
	if (trx->trx_type != NULL)
		nl_dump_line(p, "\tType: %s\n", trx->trx_type);
	nl_dump(p, "\tRF-band: %.5u\n", trx->trx_band);
	nl_dump(p, "\tEvents: busy: %u late: %u\n",
		stats->trx_event_busy, stats->trx_event_late);

	nl_dump(p, "\n");
	for (n = 0; n < 24; n++) {
		dts = &trx->trx_slots[n];
		if (!dts->dts_valid)
			continue;
		slot_dump(dts, n, p);
	}
}

static int nl_dect_transceiver_compare(struct nl_object *_a, struct nl_object *_b,
				       uint32_t attrs, int flags)
{
	struct nl_dect_transceiver *a = (struct nl_dect_transceiver *)_a;
	struct nl_dect_transceiver *b = (struct nl_dect_transceiver *)_b;
	int diff = 0;

#define TRX_DIFF(ATTR, EXPR)	ATTR_DIFF(attrs, TRANSCEIVER_ATTR_##ATTR, a, b, EXPR)

	diff |= TRX_DIFF(NAME,		strcmp(a->trx_name, b->trx_name));
	diff |= TRX_DIFF(LINK,		a->trx_link != b->trx_link);

#undef TRX_DIFF

	return diff;
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct nl_dect_transceiver *nl_dect_transceiver_alloc(void)
{
	return (struct nl_dect_transceiver *)nl_object_alloc(&nl_dect_transceiver_obj_ops);
}

void nl_dect_transceiver_get(struct nl_dect_transceiver *trx)
{
	nl_object_get((struct nl_object *)trx);
}

void nl_dect_transceiver_put(struct nl_dect_transceiver *trx)
{
	nl_object_put((struct nl_object *)trx);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

void nl_dect_transceiver_set_name(struct nl_dect_transceiver *trx, const char *name)
{
	trx->trx_name = strdup(name);
	trx->ce_mask |= TRANSCEIVER_ATTR_NAME;
}

bool nl_dect_transceiver_test_name(const struct nl_dect_transceiver *trx)
{
	return !!(trx->ce_mask & TRANSCEIVER_ATTR_NAME);
}

const char *nl_dect_transceiver_get_name(const struct nl_dect_transceiver *trx)
{
	return trx->trx_name;
}

void nl_dect_transceiver_set_type(struct nl_dect_transceiver *trx, const char *type)
{
	trx->trx_type = strdup(type);
	trx->ce_mask |= TRANSCEIVER_ATTR_TYPE;
}

bool nl_dect_transceiver_test_type(const struct nl_dect_transceiver *trx)
{
	return !!(trx->ce_mask & TRANSCEIVER_ATTR_TYPE);
}

const char *nl_dect_transceiver_get_type(const struct nl_dect_transceiver *trx)
{
	return trx->trx_type;
}

void nl_dect_transceiver_set_index(struct nl_dect_transceiver *trx, int index)
{
	trx->trx_index = index;
	trx->ce_mask |= TRANSCEIVER_ATTR_INDEX;
}

void nl_dect_transceiver_set_link(struct nl_dect_transceiver *trx, uint8_t link)
{
	trx->trx_link = link;
	trx->ce_mask |= TRANSCEIVER_ATTR_LINK;
}

static struct trans_tbl slot_states[] = {
	__ADD(DECT_SLOT_IDLE,		idle)
	__ADD(DECT_SLOT_SCANNING,	scanning)
	__ADD(DECT_SLOT_RX,		rx)
	__ADD(DECT_SLOT_TX,		tx)
};

void nl_dect_transceiver_set_band(struct nl_dect_transceiver *trx, uint8_t band)
{
	trx->trx_band = band;
	trx->ce_mask |= TRANSCEIVER_ATTR_BAND;
}

bool nl_dect_transceiver_test_band(const struct nl_dect_transceiver *trx)
{
	return !!(trx->ce_mask & TRANSCEIVER_ATTR_BAND);
}

uint8_t nl_dect_transceiver_get_band(const struct nl_dect_transceiver *trx)
{
	return trx->trx_band;
}

char *nl_dect_slot_state2str(uint8_t state, char *buf, size_t len)
{
	return __type2str(state, buf, len, slot_states,
			  ARRAY_SIZE(slot_states));
}

uint8_t nl_dect_slot_str2state(const char *str)
{
	return __str2type(str, slot_states, ARRAY_SIZE(slot_states));
}

int nl_dect_transceiver_build_msg(struct nl_msg *msg, struct nl_dect_transceiver *trx)
{
	struct dectmsg dm = {
		.dm_index	= trx->trx_index,
	};

	if (nlmsg_append(msg, &dm, sizeof(dm), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;
	if (trx->ce_mask & TRANSCEIVER_ATTR_NAME)
		NLA_PUT_STRING(msg, DECTA_TRANSCEIVER_NAME, trx->trx_name);
	if (trx->ce_mask & TRANSCEIVER_ATTR_LINK)
		NLA_PUT_U8(msg, DECTA_TRANSCEIVER_LINK, trx->trx_link);
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

/** @cond SKIP */
struct nl_object_ops nl_dect_transceiver_obj_ops = {
	.oo_name	= "nl_dect/transceiver",
	.oo_size	= sizeof(struct nl_dect_transceiver),
	.oo_free_data	= transceiver_free_data,
	.oo_dump	= {
		[NL_DUMP_LINE]	= transceiver_dump,
	},
	.oo_compare	= nl_dect_transceiver_compare,
	.oo_id_attrs	= TRANSCEIVER_ATTR_NAME,
};

/** @endcond */

/** @} */
