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

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/data.h>
#include <netlink/dect/cluster.h>
#include <netlink/dect/ari.h>
#include <linux/dect_netlink.h>
#include <linux/dect.h>

/** @cond SKIP */
#define CL_ATTR_NAME		0x0001
#define CL_ATTR_MODE		0x0002
#define CL_ATTR_PARI		0x0004
/** @endcond */

char *nl_dect_mbc_state2string(enum dect_mbc_state state,
			       char *buf, size_t len);
char *nl_dect_mbc_service2string(enum dect_mac_service_types type,
				 char *buf, size_t len);
char *nl_dect_mbc_cipher2string(enum dect_cipher_states state,
				char *buf, size_t len);

static void cluster_free_data(struct nl_object *obj)
{
	struct nl_dect_cluster *cl = nl_object_priv(obj);

	if (cl == NULL)
		return;
	free(cl->cl_name);
}

static void mbc_tb_dump(struct nl_dect_mbc_tb *mtb, struct nl_dump_params *p)
{
	nl_dump(p, "\t    TB: LBN: %u ECN: %u Cell: %u RX/TX-Slots: %u/%u\n",
		mtb->mtb_lbn, mtb->mtb_ecn,
		mtb->mtb_cell, mtb->mtb_rx_slot, mtb->mtb_tx_slot);
}

static void mbc_dump(struct nl_dect_mbc *mbc, struct nl_dump_params *p)
{
	unsigned int i;
	char buf[64];

	nl_dump(p, "\tMBC: MCEI %u\n", mbc->mbc_mcei);
	nl_dump(p, "\t  State: %s\n",
		nl_dect_mbc_state2string(mbc->mbc_state,
					 buf, sizeof(buf)));
	nl_dump(p, "\t  Service: %s\n",
		nl_dect_mbc_service2string(mbc->mbc_service,
					   buf, sizeof(buf)));
	nl_dump(p, "\t  Cipher state: %s\n",
		nl_dect_mbc_cipher2string(mbc->mbc_cipher_state,
					  buf, sizeof(buf)));
	nl_dump(p, "\t  Cs-channel RX-Bytes: %u TX-Bytes: %u\n",
		mbc->mbc_cs_rx_bytes, mbc->mbc_cs_tx_bytes);
	nl_dump(p, "\t  I-channel RX-Bytes: %u TX-Bytes: %u\n",
		mbc->mbc_i_rx_bytes, mbc->mbc_i_tx_bytes);

	for (i = 0; i < mbc->mbc_ntbs; i++)
		mbc_tb_dump(&mbc->mbc_tbs[i], p);
}

static void cluster_dump(struct nl_object *obj, struct nl_dump_params *p)
{
	struct nl_dect_cluster *cl = nl_object_priv(obj);
	unsigned int i;
	char buf[64];

	if (cl->ce_mask & CL_ATTR_NAME)
		nl_dump_line(p, "%d: DECT Cluster %s:\n",
			     cl->cl_index, cl->cl_name);

	if (cl->ce_mask & CL_ATTR_MODE)
		nl_dump_line(p, "\tMode: %s\n",
			     nl_dect_cluster_mode2str(cl->cl_mode,
				     		  buf, sizeof(buf)));

	if (cl->ce_mask & CL_ATTR_PARI) {
		nl_dump(p, "\tPARI: ");
		nl_dect_dump_ari(&cl->cl_pari, p);
		nl_dump(p, "\n");
	}

	nl_dump(p, "\n");
	for (i = 0; i < cl->cl_nmbcs; i++)
		mbc_dump(&cl->cl_mbcs[i], p);
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct nl_dect_cluster *nl_dect_cluster_alloc(void)
{
	return (struct nl_dect_cluster *)nl_object_alloc(&nl_dect_cluster_obj_ops);
}

void nl_dect_cluster_get(struct nl_dect_cluster *cl)
{
	nl_object_get((struct nl_object *)cl);
}

void nl_dect_cluster_put(struct nl_dect_cluster *cl)
{
	nl_object_put((struct nl_object *)cl);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

unsigned int nl_dect_cluster_get_index(const struct nl_dect_cluster *cl)
{
	return cl->cl_index;
}

void nl_dect_cluster_set_name(struct nl_dect_cluster *cl, const char *name)
{
	cl->cl_name = strdup(name);
	cl->ce_mask |= CL_ATTR_NAME;
}

bool nl_dect_cluster_test_name(const struct nl_dect_cluster *cl)
{
	return !!(cl->ce_mask & CL_ATTR_NAME);
}

const char *nl_dect_cluster_get_name(const struct nl_dect_cluster *cl)
{
	return cl->cl_name;
}

void nl_dect_cluster_set_mode(struct nl_dect_cluster *cl, uint8_t mode)
{
	cl->cl_mode = mode;
	cl->ce_mask |= CL_ATTR_MODE;
}

bool nl_dect_cluster_test_mode(const struct nl_dect_cluster *cl)
{
	return !!(cl->ce_mask & CL_ATTR_MODE);
}

uint8_t nl_dect_cluster_get_mode(const struct nl_dect_cluster *cl)
{
	return cl->cl_mode;
}

void nl_dect_cluster_set_pari(struct nl_dect_cluster *cl, const struct nl_dect_ari *pari)
{
	memcpy(&cl->cl_pari, pari, sizeof(cl->cl_pari));
	cl->ce_mask |= CL_ATTR_PARI;
}

bool nl_dect_cluster_test_pari(const struct nl_dect_cluster *cl)
{
	return !!(cl->ce_mask & CL_ATTR_PARI);
}

const struct nl_dect_ari *nl_dect_cluster_get_pari(const struct nl_dect_cluster *cl)
{
	return &cl->cl_pari;
}

int nl_dect_cluster_build_msg(struct nl_msg *msg, struct nl_dect_cluster *cl)
{
	struct dectmsg dm = {
		.dm_index	= cl->cl_index,
	};

	if (nlmsg_append(msg, &dm, sizeof(dm), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (cl->ce_mask & CL_ATTR_NAME)
		NLA_PUT_STRING(msg, DECTA_CLUSTER_NAME, cl->cl_name);
	if (nl_dect_fill_ari(msg, &cl->cl_pari, DECTA_CLUSTER_PARI) < 0)
		goto nla_put_failure;
	if (cl->ce_mask & CL_ATTR_MODE)
		NLA_PUT_U8(msg, DECTA_CLUSTER_MODE, cl->cl_mode);
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static struct trans_tbl cluster_modes[] = {
	__ADD(DECT_MODE_FP, FP)
	__ADD(DECT_MODE_PP, PP)
};

char *nl_dect_cluster_mode2str(enum dect_cluster_modes mode, char *buf, size_t len)
{
	return __type2str(mode, buf, len, cluster_modes,
			  ARRAY_SIZE(cluster_modes));
}

enum dect_cluster_modes nl_dect_cluster_str2mode(const char *str)
{
	return __str2type(str, cluster_modes, ARRAY_SIZE(cluster_modes));
}

static struct trans_tbl mbc_states[] = {
	__ADD(DECT_MBC_NONE,				none)
	__ADD(DECT_MBC_INITIATED,			initiated)
	__ADD(DECT_MBC_ESTABLISHED,			established)
	__ADD(DECT_MBC_RELEASED,			released)
};

char *nl_dect_mbc_state2string(enum dect_mbc_state state,
			       char *buf, size_t len)
{
	return __type2str(state, buf, len, mbc_states,
			  ARRAY_SIZE(mbc_states));
}

static struct trans_tbl mac_service_types[] = {
	__ADD(DECT_SERVICE_IN_MIN_DELAY,		IN_min_delay)
	__ADD(DECT_SERVICE_IPX_ENCODED_PROTECTED,	IPX_encoded_protected)
	__ADD(DECT_SERVICE_IN_NORMAL_DELAY,		IN_normal_delay)
	__ADD(DECT_SERVICE_UNKNOWN,			unknown)
	__ADD(DECT_SERVICE_C_CHANNEL_ONLY,		C_channel_only)
	__ADD(DECT_SERVICE_IP_ERROR_DETECTION,		IP_error_detection)
	__ADD(DECT_SERVICE_IPQ_ERROR_DETECTION,		IPQ_error_detection)
};

char *nl_dect_mbc_service2string(enum dect_mac_service_types type,
				 char *buf, size_t len)
{
	return __type2str(type, buf, len, mac_service_types,
			  ARRAY_SIZE(mac_service_types));
}

static struct trans_tbl cipher_states[] = {
	__ADD(DECT_CIPHER_DISABLED,			disabled)
	__ADD(DECT_CIPHER_ENABLED,			enabled)
};

char *nl_dect_mbc_cipher2string(enum dect_cipher_states state,
				char *buf, size_t len)
{
	return __type2str(state, buf, len, cipher_states,
			  ARRAY_SIZE(cipher_states));
}

/** @cond SKIP */
struct nl_object_ops nl_dect_cluster_obj_ops = {
	.oo_name	= "nl_dect/cluster",
	.oo_size	= sizeof(struct nl_dect_cluster),
	.oo_free_data	= cluster_free_data,
	.oo_dump	= {
		[NL_DUMP_LINE]	= cluster_dump,
	},
	.oo_id_attrs	= CL_ATTR_NAME,
};

/** @endcond */

/** @} */
