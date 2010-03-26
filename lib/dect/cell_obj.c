/*
 * lib/dect/cell.c		DECT Cell objects
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
#include <netlink/dect/cluster.h>
#include <netlink/dect/cell.h>
#include <netlink/dect/ari.h>
#include <linux/dect_netlink.h>

/** @cond SKIP */
#define CELL_ATTR_INDEX		0x0001
#define CELL_ATTR_NAME		0x0002
#define CELL_ATTR_FLAGS		0x0004
#define CELL_ATTR_TRANSCEIVER	0x0008
#define CELL_ATTR_LINK		0x0010
/** @endcond */

static void cell_free_data(struct nl_object *obj)
{
	struct nl_dect_cell *cell = nl_object_priv(obj);
	unsigned int i;

	if (cell == NULL)
		return;
	for (i = 0; i < 16; i++)
		free(cell->c_transceiver[i]);
}

static void cell_dump(struct nl_object *obj, struct nl_dump_params *p)
{
	struct nl_dect_cell *cell = nl_object_priv(obj);
	struct nl_cache *cluster_cache;
	unsigned int i;
	char buf[64];

	if (cell->ce_mask & CELL_ATTR_NAME)
		nl_dump(p, "%u: DECT Cell %s", cell->c_index, cell->c_name);

	if (cell->ce_mask & CELL_ATTR_LINK) {
		cluster_cache = nl_cache_mngt_require("nl_dect/cluster");
		if (cluster_cache != NULL) {
			nl_dect_cluster_i2name(cluster_cache, cell->c_link, buf,
					    sizeof(buf));
			nl_dump(p, "@%s", buf);
		} else
			nl_dump(p, "@%u", cell->c_link);
	}
	nl_dump(p, ":");

	if (cell->ce_mask & CELL_ATTR_FLAGS) {
		nl_dect_cell_flags2str(cell->c_flags, buf, sizeof(buf));
		nl_dump(p, " <%s>", buf);
	}
	nl_dump(p, "\n");

	if (cell->ce_mask & CELL_ATTR_TRANSCEIVER) {
		for (i = 0; i < 16 && cell->c_transceiver[i] != NULL; i++)
			nl_dump(p, "\tTransceiver: %s\n",
				cell->c_transceiver[i]);
	}

}

/**
 * @name Allocation/Freeing
 * @{
 */

struct nl_dect_cell *nl_dect_cell_alloc(void)
{
	return (struct nl_dect_cell *)nl_object_alloc(&nl_dect_cell_obj_ops);
}

void nl_dect_cell_get(struct nl_dect_cell *cell)
{
	nl_object_get((struct nl_object *)cell);
}

void nl_dect_cell_put(struct nl_dect_cell *cell)
{
	nl_object_put((struct nl_object *)cell);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

void nl_dect_cell_set_index(struct nl_dect_cell *cell, int index)
{
	cell->c_index = index;
	cell->ce_mask |= CELL_ATTR_INDEX;
}

bool nl_dect_cell_test_index(const struct nl_dect_cell *cell)
{
	return !!(cell->ce_mask & CELL_ATTR_INDEX);
}

int nl_dect_cell_get_index(const struct nl_dect_cell *cell)
{
	return cell->c_index;
}

void nl_dect_cell_set_name(struct nl_dect_cell *cell, const char *name)
{
	cell->c_name = strdup(name);
	cell->ce_mask |= CELL_ATTR_NAME;
}

bool nl_dect_cell_test_name(const struct nl_dect_cell *cell)
{
	return !!(cell->ce_mask & CELL_ATTR_NAME);
}

const char *nl_dect_cell_get_name(const struct nl_dect_cell *cell)
{
	return cell->c_name;
}

void nl_dect_cell_set_flags(struct nl_dect_cell *cell, uint32_t flags)
{
	cell->c_flags = flags;
	cell->ce_mask |= CELL_ATTR_FLAGS;
}

bool nl_dect_cell_test_flags(const struct nl_dect_cell *cell)
{
	return !!(cell->ce_mask & CELL_ATTR_FLAGS);
}

uint32_t nl_dect_cell_get_flags(const struct nl_dect_cell *cell)
{
	return cell->c_flags;
}

void nl_dect_cell_set_transceiver(struct nl_dect_cell *cell, unsigned int i,
				  const char *id)
{
	cell->c_transceiver[i] = strdup(id);
	cell->ce_mask |= CELL_ATTR_TRANSCEIVER;
}

bool nl_dect_cell_test_transceiver(const struct nl_dect_cell *cell)
{
	return !!(cell->ce_mask & CELL_ATTR_TRANSCEIVER);
}

const char *nl_dect_cell_get_transceiver(const struct nl_dect_cell *cell,
					 unsigned int i)
{
	return cell->c_transceiver[i];
}

void nl_dect_cell_set_link(struct nl_dect_cell *cell, int link)
{
	cell->c_link = link;
	cell->ce_mask |= CELL_ATTR_LINK;
}

bool nl_dect_cell_test_link(const struct nl_dect_cell *cell)
{
	return !!(cell->ce_mask & CELL_ATTR_LINK);
}

int nl_dect_cell_get_link(const struct nl_dect_cell *cell)
{
	return cell->c_link;
}

int nl_dect_cell_build_msg(struct nl_msg *msg, struct nl_dect_cell *cell)
{
	struct dectmsg dm = {
		.dm_index	= cell->c_index,
	};

	if (nlmsg_append(msg, &dm, sizeof(dm), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;
	if (cell->ce_mask & CELL_ATTR_NAME)
		NLA_PUT_STRING(msg, DECTA_CELL_NAME, cell->c_name);
	if (cell->ce_mask & CELL_ATTR_FLAGS)
		NLA_PUT_U32(msg, DECTA_CELL_FLAGS, cell->c_flags);
	if (cell->ce_mask & CELL_ATTR_LINK)
		NLA_PUT_U8(msg, DECTA_CELL_CLUSTER, cell->c_link);
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static struct trans_tbl cell_flags[] = {
	__ADD(DECT_CELL_CCP,		ccp)
	__ADD(DECT_CELL_SLAVE,		slave)
	__ADD(DECT_CELL_MONITOR,	monitor)
};

char *nl_dect_cell_flags2str(uint32_t flags, char *buf, size_t len)
{
	return __flags2str(flags, buf, len, cell_flags, ARRAY_SIZE(cell_flags));
}

uint32_t nl_dect_cell_str2flags(const char *str)
{
	return __str2flags(str, cell_flags, ARRAY_SIZE(cell_flags));
}

/** @cond SKIP */
struct nl_object_ops nl_dect_cell_obj_ops = {
	.oo_name	= "nl_dect/cell",
	.oo_size	= sizeof(struct nl_dect_cell),
	.oo_free_data	= cell_free_data,
	.oo_dump	= {
		[NL_DUMP_LINE]	= cell_dump,
	},
	.oo_id_attrs	= CELL_ATTR_NAME,
};

/** @endcond */

/** @} */
