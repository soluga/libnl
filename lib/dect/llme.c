/*
 * lib/dect/llme.c		DECT Lower Layer Management Entity Objects
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
 * @defgroup dect LLME
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/dect/dect.h>
#include <netlink/dect/ari.h>
#include <netlink/dect/llme.h>
#include <linux/dect_netlink.h>

/** @cond SKIP */
static struct nl_object_ops llme_msg_obj_ops;
/** @endcond */

#define MAC_INFO_ATTR_PARI		0x010000
#define MAC_INFO_ATTR_RPN		0x020000
#define MAC_INFO_ATTR_RSSI		0x040000
#define MAC_INFO_ATTR_FPC		0x080000
#define MAC_INFO_ATTR_HLC		0x100000
#define MAC_INFO_ATTR_EHLC		0x200000

static inline struct nl_dect_llme_mac_info *mac_info(const struct nl_dect_llme_msg *lmsg)
{
	return (void *)&lmsg->lm_mi;
}

void nl_dect_llme_mac_info_set_pari(struct nl_dect_llme_msg *lmsg,
				    const struct nl_dect_ari *pari)
{
	struct nl_dect_llme_mac_info *mi = mac_info(lmsg);

	memcpy(&mi->mi_pari, pari, sizeof(mi->mi_pari));
	lmsg->ce_mask |= MAC_INFO_ATTR_PARI;
}

const struct nl_dect_ari *nl_dect_llme_mac_info_get_pari(const struct nl_dect_llme_msg *lmsg)
{
	return &mac_info(lmsg)->mi_pari;
}

void nl_dect_llme_mac_info_set_rpn(struct nl_dect_llme_msg *lmsg, uint8_t rpn)
{
	mac_info(lmsg)->mi_rpn = rpn;
	lmsg->ce_mask |= MAC_INFO_ATTR_RPN;
}

uint8_t nl_dect_llme_mac_info_get_rpn(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_rpn;
}

void nl_dect_llme_mac_info_set_rssi(struct nl_dect_llme_msg *lmsg, uint8_t rssi)
{
	mac_info(lmsg)->mi_rssi = rssi;
	lmsg->ce_mask |= MAC_INFO_ATTR_RSSI;
}

uint8_t nl_dect_llme_mac_info_get_rssi(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_rssi;
}

void nl_dect_llme_mac_info_set_fpc(struct nl_dect_llme_msg *lmsg, uint32_t fpc)
{
	mac_info(lmsg)->mi_fpc = fpc;
	lmsg->ce_mask |= MAC_INFO_ATTR_FPC;
}

uint32_t nl_dect_llme_mac_info_get_fpc(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_fpc;
}

void nl_dect_llme_mac_info_set_hlc(struct nl_dect_llme_msg *lmsg, uint16_t hlc)
{
	mac_info(lmsg)->mi_hlc = hlc;
	lmsg->ce_mask |= MAC_INFO_ATTR_HLC;
}

uint16_t nl_dect_llme_mac_info_get_hlc(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_hlc;
}

void nl_dect_llme_mac_info_set_ehlc(struct nl_dect_llme_msg *lmsg, uint16_t ehlc)
{
	mac_info(lmsg)->mi_ehlc = ehlc;
	lmsg->ce_mask |= MAC_INFO_ATTR_EHLC;
}

uint16_t nl_dect_llme_mac_info_get_ehlc(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_ehlc;
}

static struct trans_tbl fixed_part_capabilities[] = {
	__ADD(DECT_FPC_EXTENDED_FP_INFO,		extended_fp_info)
	__ADD(DECT_FPC_DOUBLE_DUPLEX_BEARER_CONNECTION,	double_duplex_bearer_connection)
	__ADD(DECT_FPC_RESERVED,			reserved)
	__ADD(DECT_FPC_DOUBLE_SLOT,			double_slot)
	__ADD(DECT_FPC_HALF_SLOT,			half_slot)
	__ADD(DECT_FPC_FULL_SLOT,			full_slot)
	__ADD(DECT_FPC_FREQ_CONTROL,			frequency_control)
	__ADD(DECT_FPC_PAGE_REPETITION,			page_repetition)
	__ADD(DECT_FPC_CO_SETUP_ON_DUMMY,		co_setup_on_dummy)
	__ADD(DECT_FPC_CL_UPLINK,			cl_uplink)
	__ADD(DECT_FPC_CL_DOWNLINK,			cl_downlink)
	__ADD(DECT_FPC_BASIC_A_FIELD_SETUP,		basic_a_field_setup)
	__ADD(DECT_FPC_ADV_A_FIELD_SETUP,		advanced_a_field_setup)
	__ADD(DECT_FPC_B_FIELD_SETUP,			b_field_setup)
	__ADD(DECT_FPC_CF_MESSAGES,			cf_messages)
	__ADD(DECT_FPC_IN_MIN_DELAY,			in_min_delay)
	__ADD(DECT_FPC_IN_NORM_DELAY,			in_normal_delay)
	__ADD(DECT_FPC_IP_ERROR_DETECTION,		ip_error_detection)
	__ADD(DECT_FPC_IP_ERROR_CORRECTION,		ip_error_correction)
	__ADD(DECT_FPC_MULTIBEARER_CONNECTIONS,		multibearer_connections)
};

char *nl_dect_llme_fpc2str(uint32_t fpc, char *buf, size_t len)
{
	return __flags2str(fpc, buf, len, fixed_part_capabilities,
			   ARRAY_SIZE(fixed_part_capabilities));
}

uint32_t nl_dect_llme_str2fpc(const char *str)
{
	return __str2flags(str, fixed_part_capabilities,
			   ARRAY_SIZE(fixed_part_capabilities));
}

static struct trans_tbl higher_layer_capabilities[] = {
	__ADD(DECT_HLC_ADPCM_G721_VOICE,		adpcm_g721_voice)
	__ADD(DECT_HLC_GAP_PAP_BASIC_SPEECH,		gap_pap_basic_speech)
	__ADD(DECT_HLC_NON_VOICE_CIRCUIT_SWITCHED,	non_voice_circuit_switched_service)
	__ADD(DECT_HLC_NON_VOICE_PACKET_SWITCHED,	non_voice_packet_switched_service)
	__ADD(DECT_HLC_STANDARD_AUTHENTICATION,		standard_authentication)
	__ADD(DECT_HLC_STANDARD_CIPHERING,		standard_ciphering)
	__ADD(DECT_HLC_LOCATION_REGISTRATION,		location_registration)
	__ADD(DECT_HLC_SIM_SERVICES,			sim_services)
	__ADD(DECT_HLC_NON_STATIC_FIXED_PART,		non_static_fixed_part)
	__ADD(DECT_HLC_CISS_SERVICE,			ciss_service)
	__ADD(DECT_HLC_CLMS_SERVICE,			clms_service)
	__ADD(DECT_HLC_COMS_SERVICE,			coms_service)
	__ADD(DECT_HLC_ACCESS_RIGHT_REQUESTS,		access_right_requests)
	__ADD(DECT_HLC_EXTERNAL_HANDOVER,		external_handover)
	__ADD(DECT_HLC_CONNECTION_HANDOVER,		connection_handover)
	__ADD(DECT_HLC_RESERVED,			reserved)
};

char *nl_dect_llme_hlc2str(uint16_t hlc, char *buf, size_t len)
{
	return __flags2str(hlc, buf, len, higher_layer_capabilities,
			   ARRAY_SIZE(higher_layer_capabilities));
}

uint16_t nl_dect_llme_str2hlc(const char *str)
{
	return __str2flags(str, higher_layer_capabilities,
			   ARRAY_SIZE(higher_layer_capabilities));
}

static struct trans_tbl extended_higher_layer_capabilities[] = {
	__ADD(DECT_EHLC_ISDN_DATA_SERVICE,		isdn_data_service)
	__ADD(DECT_EHLC_DATA_SERVICE_PROFILE_A_B,	data_service_profile_a_b)
	__ADD(DECT_EHLC_DATA_SERVICE_PROFILE_C,		data_service_profile_c)
	__ADD(DECT_EHLC_DATA_SERVICE_PROFILE_D,		data_service_profile_d)
	__ADD(DECT_EHLC_DATA_SERVICE_PROFILE_E,		data_service_profile_e)
	__ADD(DECT_EHLC_DATA_SERVICE_PROFILE_F,		data_service_profile_f)
	__ADD(DECT_EHLC_ASYMETRIC_BEARERS,		asymetric_bearers)
	__ADD(DECT_EHLC_TPUI_LOCATION_REGISTRATION,	tpui_location_registration)
};

char *nl_dect_llme_ehlc2str(uint16_t ehlc, char *buf, size_t len)
{
	return __flags2str(ehlc, buf, len, extended_higher_layer_capabilities,
			   ARRAY_SIZE(extended_higher_layer_capabilities));
}

uint16_t nl_dect_llme_str2ehlc(const char *str)
{
	return __str2flags(str, extended_higher_layer_capabilities,
			   ARRAY_SIZE(extended_higher_layer_capabilities));
}

static void nl_dect_llme_mac_info_dump(const struct nl_dect_llme_msg *lmsg,
				    struct nl_dump_params *p)
{
	const struct nl_dect_llme_mac_info *mi = mac_info(lmsg);
	char buf[256];

	if (lmsg->ce_mask & MAC_INFO_ATTR_PARI) {
		nl_dump(p, "\tARI: ");
		nl_dect_dump_ari(&mi->mi_pari, p);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_RPN)
		nl_dump(p, " RPN: %x", mi->mi_rpn);
	if (lmsg->ce_mask & MAC_INFO_ATTR_RSSI)
		nl_dump(p, " signal level: %.2fdBm", nl_dect_rssi_to_dbm(mi->mi_rssi));
	if (lmsg->ce_mask & MAC_INFO_ATTR_FPC) {
		nl_dect_llme_fpc2str(mi->mi_fpc, buf, sizeof(buf));
		nl_dump(p, "\n\tMAC layer capabilities: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_HLC) {
		nl_dect_llme_hlc2str(mi->mi_hlc, buf, sizeof(buf));
		nl_dump(p, "\n\tHigher layer capabilities: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_EHLC) {
		nl_dect_llme_ehlc2str(mi->mi_ehlc, buf, sizeof(buf));
		nl_dump(p, "\n\tExtended higher layer capabilities: %s", buf);
	}
	nl_dump(p, "\n");
}

static struct nla_policy nl_dect_efpc_policy[DECTA_EFPC_MAX + 1] = {
	[DECTA_EFPC_CRFP_HOPS]		= { .type = NLA_U8 },
	[DECTA_EFPC_CRFP_ENCRYPTION]	= { },
	[DECTA_EFPC_REP_HOPS]		= { .type = NLA_U8 },
	[DECTA_EFPC_REP_INTERLACING]	= { },
	[DECTA_EFPC_EHLC]		= { .type = NLA_U16 },
};

static struct nla_policy nl_dect_mac_info_policy[DECTA_MAC_INFO_MAX + 1] =  {
	[DECTA_MAC_INFO_PARI]		= { .type = NLA_NESTED },
	[DECTA_MAC_INFO_RPN]		= { .type = NLA_U8 },
	[DECTA_MAC_INFO_RSSI]		= { .type = NLA_U8 },
	[DECTA_MAC_INFO_SARI_LIST]	= { .type = NLA_NESTED },
	[DECTA_MAC_INFO_FPC]		= { .type = NLA_U32 },
	[DECTA_MAC_INFO_HLC]		= { .type = NLA_U16 },
	[DECTA_MAC_INFO_EFPC]		= { .type = NLA_NESTED },
};

static int nl_dect_llme_mac_info_parse(struct nl_dect_llme_msg *lmsg,
				       struct nlattr *tb[])
{
	struct nl_dect_ari pari;
	int err;

	if (tb[DECTA_MAC_INFO_PARI] != NULL) {
		err = nl_dect_parse_ari(&pari, tb[DECTA_MAC_INFO_PARI]);
		if (err < 0)
			return err;
		nl_dect_llme_mac_info_set_pari(lmsg, &pari);
	}
	if (tb[DECTA_MAC_INFO_RPN] != NULL)
		nl_dect_llme_mac_info_set_rpn(lmsg, nla_get_u8(tb[DECTA_MAC_INFO_RPN]));
	if (tb[DECTA_MAC_INFO_RSSI] != NULL)
		nl_dect_llme_mac_info_set_rssi(lmsg, nla_get_u8(tb[DECTA_MAC_INFO_RSSI]));
	if (tb[DECTA_MAC_INFO_FPC] != NULL)
		nl_dect_llme_mac_info_set_fpc(lmsg, nla_get_u32(tb[DECTA_MAC_INFO_FPC]));
	if (tb[DECTA_MAC_INFO_HLC] != NULL)
		nl_dect_llme_mac_info_set_hlc(lmsg, nla_get_u16(tb[DECTA_MAC_INFO_HLC]));
	if (tb[DECTA_MAC_INFO_EFPC] != NULL) {
		struct nlattr *nla[DECTA_EFPC_MAX + 1];

		err = nla_parse_nested(nla, DECTA_EFPC_MAX, tb[DECTA_MAC_INFO_EFPC],
				       nl_dect_efpc_policy);
		if (err < 0)
			return err;
		nl_dect_llme_mac_info_set_ehlc(lmsg, nla_get_u16(nla[DECTA_EFPC_EHLC]));
	}
	return 0;
}

static int nl_dect_llme_mac_info_build(struct nl_msg *msg,
				       struct nl_dect_llme_msg *lmsg)
{
	struct nl_dect_llme_mac_info *mi = mac_info(lmsg);
	int err;

	if (lmsg->ce_mask & MAC_INFO_ATTR_PARI) {
		err = nl_dect_fill_ari(msg, &mi->mi_pari, DECTA_MAC_INFO_PARI);
		if (err < 0)
			return err;
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_RPN)
		NLA_PUT_U8(msg, DECTA_MAC_INFO_RPN, mi->mi_rpn);
	if (lmsg->ce_mask & MAC_INFO_ATTR_FPC)
		NLA_PUT_U32(msg, DECTA_MAC_INFO_FPC, mi->mi_fpc);
#ifdef FIXME
	if (lmsg->ce_mask & MAC_INFO_ATTR_EHLC)
		NLA_PUT_U16(msg, DECTA_MAC_INFO_EHLC, mi->mi_ehlc);
#endif
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

#if 0
#define MAC_CON_ATTR_MCEI		0x010000
#define MAC_CON_ATTR_ARI		0x020000
#define MAC_CON_ATTR_PMID		0x040000
#define MAC_CON_ATTR_TYPE		0x080000
#define MAC_CON_ATTR_ECN		0x100000
#define MAC_CON_ATTR_SERVICE		0x200000

static inline struct nl_dect_llme_mac_con *mac_con(const struct nl_dect_llme_msg *lmsg)
{
	return (void *)&lmsg->lm_mc;
}

void nl_dect_llme_mac_con_set_mcei(struct nl_dect_llme_msg *lmsg, uint32_t mcei)
{
	mac_con(lmsg)->mc_mcei = mcei;
	lmsg->ce_mask |= MAC_CON_ATTR_MCEI;
}

uint32_t nl_dect_llme_mac_con_get_mcei(const struct nl_dect_llme_msg *lmsg)
{
	return mac_con(lmsg)->mc_mcei;
}

void nl_dect_llme_mac_con_set_ari(struct nl_dect_llme_msg *lmsg, const struct nl_dect_ari *ari)
{
	struct nl_dect_llme_mac_con *mc = mac_con(lmsg);

	memcpy(&mc->mc_ari, ari, sizeof(mc->mc_ari));
	lmsg->ce_mask |= MAC_CON_ATTR_ARI;
}

const struct nl_dect_ari *nl_dect_llme_mac_con_get_ari(const struct nl_dect_llme_msg *lmsg)
{
	return &mac_con(lmsg)->mc_ari;
}

void nl_dect_llme_mac_con_set_pmid(struct nl_dect_llme_msg *lmsg, uint32_t pmid)
{
	mac_con(lmsg)->mc_pmid = pmid;
	lmsg->ce_mask |= MAC_CON_ATTR_PMID;
}

uint32_t nl_dect_llme_mac_con_get_pmid(const struct nl_dect_llme_msg *lmsg)
{
	return mac_con(lmsg)->mc_pmid;
}

void nl_dect_llme_mac_con_set_type(struct nl_dect_llme_msg *lmsg,
				enum nl_dect_mac_con_types type)
{
	mac_con(lmsg)->mc_type = type;
	lmsg->ce_mask |= MAC_CON_ATTR_TYPE;
}

enum nl_dect_mac_con_types nl_dect_llme_mac_con_get_type(const struct nl_dect_llme_msg *lmsg)
{
	return mac_con(lmsg)->mc_type;
}

void nl_dect_llme_mac_con_set_ecn(struct nl_dect_llme_msg *lmsg, uint8_t ecn)
{
	mac_con(lmsg)->mc_ecn = ecn;
	lmsg->ce_mask |= MAC_CON_ATTR_ECN;
}

uint8_t nl_dect_llme_mac_con_get_ecn(const struct nl_dect_llme_msg *lmsg)
{
	return mac_con(lmsg)->mc_ecn;
}

void nl_dect_llme_mac_con_set_service(struct nl_dect_llme_msg *lmsg,
				   enum nl_dect_mac_con_service_types service)
{
	mac_con(lmsg)->mc_service = service;
	lmsg->ce_mask |= MAC_CON_ATTR_SERVICE;
}

enum nl_dect_mac_con_service_types
nl_dect_llme_mac_con_get_service(const struct nl_dect_llme_msg *lmsg)
{
	return mac_con(lmsg)->mc_service;
}

static struct trans_tbl con_types[] = {
	__ADD(DECT_MAC_CON_BASIC,		basic)
	__ADD(DECT_MAC_CON_ADVANCED,		advanced)
};

char *nl_dect_llme_contype2str(enum nl_dect_mac_con_types type, char *buf, size_t len)
{
	return __type2str(type, buf, len, con_types, ARRAY_SIZE(con_types));
}

enum nl_dect_mac_con_types nl_dect_llme_str2contype(const char *str)
{
	return __str2type(str, con_types, ARRAY_SIZE(con_types));
}

static struct trans_tbl service_types[] = {
	__ADD(DECT_MAC_CON_IN_MIN_DELAY,	I_N_minimal_delay)
	__ADD(DECT_MAC_CON_IN_NORM_DELAY,	I_N_normal_delay)
	__ADD(DECT_MAC_CON_IP_ERROR_DETECTION,	I_P_error_detection)
	__ADD(DECT_MAC_CON_IP_ERROR_CORRECTION,	I_P_error_correction)
	__ADD(DECT_MAC_CON_UNKNOWN,		unknown)
	__ADD(DECT_MAC_CON_C_ONLY,		C_only)
};

char *nl_dect_llme_service2str(enum nl_dect_mac_con_service_types service,
			    char *buf, size_t len)
{
	return __type2str(service, buf, len, service_types,
			   ARRAY_SIZE(service_types));
}

enum nl_dect_mac_con_service_types nl_dect_llme_str2service(const char *str)
{
	return __str2type(str, service_types, ARRAY_SIZE(service_types));
}

static void nl_dect_llme_mac_con_dump(const struct nl_dect_llme_msg *lmsg,
				   struct nl_dump_params *p)
{
	const struct nl_dect_llme_mac_con *mc = mac_con(lmsg);
	char buf[256];

	nl_dump(p, "\t");
	if (lmsg->ce_mask & MAC_CON_ATTR_MCEI)
		nl_dump(p, "MCEI %x: ", mc->mc_mcei);
	if (lmsg->ce_mask & MAC_CON_ATTR_PMID)
		nl_dump(p, "PMID: %x ", mc->mc_pmid);
	if (lmsg->ce_mask & MAC_CON_ATTR_ARI) {
		nl_dump(p, "=> ");
		nl_dect_dump_ari(&mc->mc_ari, p);
		nl_dump(p, " ");
	}
	if (lmsg->ce_mask & MAC_CON_ATTR_ECN)
		nl_dump(p, "ECN: %x ", mc->mc_ecn);
	nl_dump(p, "\n");

	if (lmsg->ce_mask & MAC_CON_ATTR_TYPE) {
		nl_dect_llme_contype2str(mc->mc_type, buf, sizeof(buf));
		nl_dump(p, "\tType: %s\n", buf);
	}
	if (lmsg->ce_mask & MAC_CON_ATTR_SERVICE) {
		nl_dect_llme_service2str(mc->mc_service, buf, sizeof(buf));
		nl_dump(p, "\tService: %s\n", buf);
	}
	nl_dump(p, "\n");
}

static struct nla_policy nl_dect_mac_con_policy[DECTA_MAC_CON_MAX + 1] = {
	[DECTA_MAC_CON_MCEI]		= { .type = NLA_U32 },
	[DECTA_MAC_CON_ARI]		= { .type = NLA_NESTED },
	[DECTA_MAC_CON_PMID]		= { .type = NLA_U32 },
	[DECTA_MAC_CON_TYPE]		= { .type = NLA_U8 },
	[DECTA_MAC_CON_ECN]		= { .type = NLA_U8 },
	[DECTA_MAC_CON_SERVICE]		= { .type = NLA_U8 },
};

static int nl_dect_llme_mac_con_parse(struct nl_dect_llme_msg *lmsg,
				   struct nlattr *tb[])
{
	struct nl_dect_ari ari;
	int err;

	if (tb[DECTA_MAC_CON_MCEI] != NULL)
		nl_dect_llme_mac_con_set_mcei(lmsg, nla_get_u32(tb[DECTA_MAC_CON_MCEI]));
	if (tb[DECTA_MAC_CON_ARI] != NULL) {
		err = nl_dect_parse_ari(&ari, tb[DECTA_MAC_CON_ARI]);
		if (err < 0)
			return err;
		nl_dect_llme_mac_con_set_ari(lmsg, &ari);
	}
	if (tb[DECTA_MAC_CON_PMID] != NULL)
		nl_dect_llme_mac_con_set_pmid(lmsg, nla_get_u32(tb[DECTA_MAC_CON_PMID]));
	if (tb[DECTA_MAC_CON_TYPE] != NULL)
		nl_dect_llme_mac_con_set_type(lmsg, nla_get_u8(tb[DECTA_MAC_CON_TYPE]));
	if (tb[DECTA_MAC_CON_ECN] != NULL)
		nl_dect_llme_mac_con_set_ecn(lmsg, nla_get_u8(tb[DECTA_MAC_CON_ECN]));
	if (tb[DECTA_MAC_CON_SERVICE] != NULL)
		nl_dect_llme_mac_con_set_service(lmsg, nla_get_u8(tb[DECTA_MAC_CON_SERVICE]));
	return 0;
}

static int nl_dect_llme_mac_con_build(struct nl_msg *msg,
				   struct nl_dect_llme_msg *lmsg)
{
	struct nl_dect_llme_mac_con *mc = mac_con(lmsg);
	int err;

	if (lmsg->ce_mask & MAC_CON_ATTR_MCEI)
		NLA_PUT_U32(msg, DECTA_MAC_CON_MCEI, mc->mc_mcei);
	if (lmsg->ce_mask & MAC_CON_ATTR_ARI) {
		err = nl_dect_fill_ari(msg, &mc->mc_ari, DECTA_MAC_CON_ARI);
		if (err < 0)
			goto nla_put_failure;
	}
	if (lmsg->ce_mask & MAC_CON_ATTR_PMID)
		NLA_PUT_U32(msg, DECTA_MAC_CON_PMID, mc->mc_pmid);
	if (lmsg->ce_mask & MAC_CON_ATTR_TYPE)
		NLA_PUT_U8(msg, DECTA_MAC_CON_TYPE, mc->mc_type);
	if (lmsg->ce_mask & MAC_CON_ATTR_ECN)
		NLA_PUT_U8(msg, DECTA_MAC_CON_ECN, mc->mc_ecn);
	if (lmsg->ce_mask & MAC_CON_ATTR_SERVICE)
		NLA_PUT_U8(msg, DECTA_MAC_CON_SERVICE, mc->mc_service);
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}
#endif

static const struct nl_dect_llme_link {
	int (*parse)(struct nl_dect_llme_msg *, struct nlattr *[]);
	int (*build)(struct nl_msg *, struct nl_dect_llme_msg *);
	void (*dump)(const struct nl_dect_llme_msg *, struct nl_dump_params *);
	struct nla_policy *policy;
	unsigned int maxtype;
} nl_dect_llme_dispatch[DECT_LLME_MAX + 1] = {
	[DECT_LLME_SCAN] = {
		.policy		= nl_dect_mac_info_policy,
		.maxtype	= DECTA_MAC_INFO_MAX,
		.parse		= nl_dect_llme_mac_info_parse,
		.build		= nl_dect_llme_mac_info_build,
		.dump		= nl_dect_llme_mac_info_dump,
	},
	[DECT_LLME_MAC_INFO] = {
		.policy		= nl_dect_mac_info_policy,
		.maxtype	= DECTA_MAC_INFO_MAX,
		.parse		= nl_dect_llme_mac_info_parse,
		.build		= nl_dect_llme_mac_info_build,
		.dump		= nl_dect_llme_mac_info_dump,
	},
#if 0
	[DECT_LLME_MAC_CON] = {
		.policy		= nl_dect_mac_con_policy,
		.maxtype	= DECTA_MAC_CON_MAX,
		.parse		= nl_dect_llme_mac_con_parse,
		.build		= nl_dect_llme_mac_con_build,
		.dump		= nl_dect_llme_mac_con_dump,
	},
#endif
};

static void llme_msg_dump(struct nl_object *obj, struct nl_dump_params *p)
{
	struct nl_dect_llme_msg *lmsg = nl_object_priv(obj);
	const struct nl_dect_llme_link *link;
	char buf1[64], buf2[64];

	nl_dect_llme_msgtype2str(lmsg->lm_type, buf1, sizeof(buf1));
	nl_dect_llme_op2str(lmsg->lm_op, buf2, sizeof(buf2));
	nl_dump(p, "%s-%s:\n", buf1, buf2);

	link = &nl_dect_llme_dispatch[lmsg->lm_type];
	link->dump(lmsg, p);
}

static struct nla_policy nl_dect_llme_policy[DECTA_LLME_MAX + 1] = {
	[DECTA_LLME_OP]		= { .type = NLA_U8 },
	[DECTA_LLME_TYPE]	= { .type = NLA_U8 },
	[DECTA_LLME_DATA]	= { .type = NLA_NESTED },
};

static int llme_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			   struct nlmsghdr *n, struct nl_parser_param *pp)
{
	const struct nl_dect_llme_link *link;
	struct dectmsg *dm = nlmsg_data(n);
	struct nlattr *tb[DECTA_LLME_MAX + 1];
	struct nl_dect_llme_msg *lmsg;
	uint8_t op, type;
	int err;

	err = nlmsg_parse(n, sizeof(*dm), tb, DECTA_LLME_MAX, nl_dect_llme_policy);
	if (err < 0)
		return err;

	if (tb[DECTA_LLME_OP] == NULL ||
	    tb[DECTA_LLME_TYPE] == NULL ||
	    tb[DECTA_LLME_DATA] == NULL)
		return -NLE_INVAL;

	type = nla_get_u8(tb[DECTA_LLME_TYPE]);
	if (type > DECT_LLME_MAX)
		return -NLE_INVAL;
	link = &nl_dect_llme_dispatch[type];

	op = nla_get_u8(tb[DECTA_LLME_OP]);
	switch (op) {
	case DECT_LLME_REQUEST:
	case DECT_LLME_INDICATE:
	case DECT_LLME_RESPONSE:
	case DECT_LLME_CONFIRM:
		if (link->parse == NULL)
			return -NLE_OPNOTSUPP;
		break;
	default:
		return -NLE_INVAL;
	}

	lmsg = nl_dect_llme_msg_alloc();
	lmsg->ce_msgtype = n->nlmsg_type;
	lmsg->lm_index = dm->dm_index;

	nl_dect_llme_msg_set_type(lmsg, type);
	nl_dect_llme_msg_set_op(lmsg, op);

	if (1) {
		struct nlattr *nla[link->maxtype + 1];

		err = nla_parse_nested(nla, link->maxtype, tb[DECTA_LLME_DATA],
				       link->policy);
		if (err < 0)
			goto errout;
		err = link->parse(lmsg, nla);
		if (err < 0)
			goto errout;
	}

	err = pp->pp_cb((struct nl_object *)lmsg, pp);
errout:
	nl_dect_llme_msg_put(lmsg);
	return err;
}

/**
 * @name message creation
 * @{
 */

static int nl_dect_llme_build_msg(struct nl_msg *msg, struct nl_dect_llme_msg *lmsg,
				  enum dect_llme_ops op)
{
	const struct nl_dect_llme_link *link;
	struct nlattr *nest;
	struct dectmsg dm = {
		.dm_index = lmsg->lm_index,
	};

	if (nlmsg_append(msg, &dm, sizeof(dm), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;
	NLA_PUT_U8(msg, DECTA_LLME_OP, op);
	NLA_PUT_U8(msg, DECTA_LLME_TYPE, lmsg->lm_type);

	link = &nl_dect_llme_dispatch[lmsg->lm_type];
	nest = nla_nest_start(msg, DECTA_LLME_DATA);
	if (nest == NULL)
		goto nla_put_failure;
	if (link->build(msg, lmsg) < 0)
		goto nla_put_failure;
	nla_nest_end(msg, nest);

	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int build_llme_msg(struct nl_dect_llme_msg *tmpl, enum dect_llme_ops op,
			  struct nl_msg **result)
{
	struct nl_msg *msg;
	int err;

	if (!(msg = nlmsg_alloc_simple(DECT_LLME_MSG, 0)))
		return -NLE_NOMEM;

	if ((err = nl_dect_llme_build_msg(msg, tmpl, op)) < 0) {
		nlmsg_free(msg);
		return err;
	}

	*result = msg;
	return 0;
}

int nl_dect_llme_build_request(struct nl_dect_llme_msg *tmpl,
			    struct nl_msg **result)
{
	return build_llme_msg(tmpl, DECT_LLME_REQUEST, result);
}

int nl_dect_llme_request(struct nl_sock *sk, struct nl_dect_llme_msg *lmsg)
{
	struct nl_msg *msg;
	int err;

	if ((err = nl_dect_llme_build_request(lmsg, &msg)) < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

int nl_dect_llme_build_response(struct nl_dect_llme_msg *tmpl,
			     struct nl_msg **result)
{
	return build_llme_msg(tmpl, DECT_LLME_RESPONSE, result);
}

int nl_dect_llme_respond(struct nl_sock *sk, struct nl_dect_llme_msg *tmpl)
{
	struct nl_msg *msg;
	int err;

	if ((err = nl_dect_llme_build_response(tmpl, &msg)) < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

void nl_dect_llme_msg_set_index(struct nl_dect_llme_msg *lmsg, int index)
{
	lmsg->lm_index = index;
}

void nl_dect_llme_msg_set_type(struct nl_dect_llme_msg *lmsg,
			       enum dect_llme_msg_types type)
{
	lmsg->lm_type = type;
}

enum dect_llme_msg_types nl_dect_llme_msg_get_type(const struct nl_dect_llme_msg *lmsg)
{
	return lmsg->lm_type;
}

enum dect_llme_ops nl_dect_llme_msg_get_op(const struct nl_dect_llme_msg *lmsg)
{
	return lmsg->lm_op;
}

void nl_dect_llme_msg_set_op(struct nl_dect_llme_msg *lmsg, enum dect_llme_ops op)
{
	lmsg->lm_op = op;
}

/** @} */

/**
 * @name Allocation/Freeing
 * @{
 */

struct nl_dect_llme_msg *nl_dect_llme_msg_alloc(void)
{
	return (struct nl_dect_llme_msg *)nl_object_alloc(&llme_msg_obj_ops);
}

void nl_dect_llme_msg_get(struct nl_dect_llme_msg *lmsg)
{
	nl_object_get((struct nl_object *)lmsg);
}

void nl_dect_llme_msg_put(struct nl_dect_llme_msg *lmsg)
{
	nl_object_put((struct nl_object *)lmsg);
}

/** @} */

static struct trans_tbl llme_types[] = {
	__ADD(DECT_LLME_SCAN,		SCAN)
	__ADD(DECT_LLME_MAC_INFO,	MAC_INFO)
#if 0
	__ADD(DECT_LLME_MAC_CON,	MAC_CON)
#endif
};

char *nl_dect_llme_msgtype2str(enum dect_llme_msg_types type, char *buf, size_t len)
{
	return __type2str(type, buf, len, llme_types, ARRAY_SIZE(llme_types));
}

enum dect_llme_msg_types nl_dect_llme_str2msgtype(const char *str)
{
	return __str2type(str, llme_types, ARRAY_SIZE(llme_types));
}

static struct trans_tbl llme_ops[] = {
	__ADD(DECT_LLME_REQUEST,	req)
	__ADD(DECT_LLME_INDICATE,	ind)
	__ADD(DECT_LLME_RESPONSE,	res)
	__ADD(DECT_LLME_CONFIRM,	cfm)
};

char *nl_dect_llme_op2str(enum dect_llme_ops op, char *buf, size_t len)
{
	return __type2str(op, buf, len, llme_ops, ARRAY_SIZE(llme_ops));
}

enum dect_llme_ops nl_dect_llme_str2op(const char *str)
{
	return __str2type(str, llme_ops, ARRAY_SIZE(llme_ops));
}

/** @cond SKIP */
static struct nl_object_ops llme_msg_obj_ops = {
	.oo_name	= "nl_dect/llme_msg",
	.oo_size	= sizeof(struct nl_dect_llme_msg),
	.oo_dump	= {
		[NL_DUMP_LINE]	= llme_msg_dump,
	},
};

static struct nl_cache_ops nl_dect_llme_msg_ops = {
	.co_name		= "nl_dect/llme_msg",
	.co_protocol		= NETLINK_DECT,
	.co_msgtypes		= {
		{ DECT_LLME_MSG, NL_ACT_NEW, "new" },
		END_OF_MSGTYPES_LIST,
	},
	.co_msg_parser		= llme_msg_parser,
	.co_obj_ops		= &llme_msg_obj_ops,
};
/** @endcond */

static void __init llme_init(void)
{
	nl_cache_mngt_register(&nl_dect_llme_msg_ops);
}

static void __exit llme_exit(void)
{
	nl_cache_mngt_unregister(&nl_dect_llme_msg_ops);
}

/** @} */
