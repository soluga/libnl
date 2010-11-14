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

#define MAC_INFO_ATTR_PARI		0x0010000
#define MAC_INFO_ATTR_RPN		0x0020000
#define MAC_INFO_ATTR_RSSI		0x0040000
#define MAC_INFO_ATTR_FPC		0x0080000
#define MAC_INFO_ATTR_HLC		0x0100000
#define MAC_INFO_ATTR_EFPC		0x0200000
#define MAC_INFO_ATTR_EHLC		0x0400000
#define MAC_INFO_ATTR_EFPC2		0x0800000
#define MAC_INFO_ATTR_EHLC2		0x1000000

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

bool nl_dect_llme_mac_info_test_pari(const struct nl_dect_llme_msg *lmsg)
{
	return !!(lmsg->ce_mask & MAC_INFO_ATTR_PARI);
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

void nl_dect_llme_mac_info_set_efpc(struct nl_dect_llme_msg *lmsg, uint16_t efpc)
{
	mac_info(lmsg)->mi_efpc = efpc;
	lmsg->ce_mask |= MAC_INFO_ATTR_EFPC;
}

uint16_t nl_dect_llme_mac_info_get_efpc(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_efpc;
}

void nl_dect_llme_mac_info_set_ehlc(struct nl_dect_llme_msg *lmsg, uint32_t ehlc)
{
	mac_info(lmsg)->mi_ehlc = ehlc;
	lmsg->ce_mask |= MAC_INFO_ATTR_EHLC;
}

uint32_t nl_dect_llme_mac_info_get_ehlc(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_ehlc;
}

void nl_dect_llme_mac_info_set_efpc2(struct nl_dect_llme_msg *lmsg, uint16_t efpc2)
{
	mac_info(lmsg)->mi_efpc2 = efpc2;
	lmsg->ce_mask |= MAC_INFO_ATTR_EFPC2;
}

uint16_t nl_dect_llme_mac_info_get_efpc2(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_efpc2;
}

void nl_dect_llme_mac_info_set_ehlc2(struct nl_dect_llme_msg *lmsg, uint32_t ehlc2)
{
	mac_info(lmsg)->mi_ehlc2 = ehlc2;
	lmsg->ce_mask |= MAC_INFO_ATTR_EHLC2;
}

uint32_t nl_dect_llme_mac_info_get_ehlc2(const struct nl_dect_llme_msg *lmsg)
{
	return mac_info(lmsg)->mi_ehlc2;
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
	__ADD(DECT_HLC_ACCESS_RIGHTS_REQUESTS,		access_rights_requests)
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

static struct trans_tbl extended_fixed_part_capabilities[] = {
	__ADD(DECT_EFPC_SYNC_PROLONGED_PREAMBLE,	prolonged_preamble)
	__ADD(DECT_EFPC_MAC_SUSPEND_RESUME,		suspend_resume)
	__ADD(DECT_EFPC_MAC_IP_Q_SERVICE,		ip_q_service)
	__ADD(DECT_EFPC_EXTENDED_FP_INFO2,		extended_fp_info2)
};

char *nl_dect_llme_efpc2str(uint16_t efpc, char *buf, size_t len)
{
	return __flags2str(efpc, buf, len, extended_fixed_part_capabilities,
			   ARRAY_SIZE(extended_fixed_part_capabilities));
}

uint16_t nl_dect_llme_str2efpc(const char *str)
{
	return __str2flags(str, extended_fixed_part_capabilities,
			   ARRAY_SIZE(extended_fixed_part_capabilities));
}
static struct trans_tbl extended_higher_layer_capabilities[] = {
	__ADD(DECT_EHLC_ISDN_DATA_SERVICE,		isdn_data_service)
	__ADD(DECT_EHLC_DPRS_FREL,			dprs_frel)
	__ADD(DECT_EHLC_DPRS_STREAM,			dprs_stream)
	__ADD(DECT_EHLC_DATA_SERVICE_PROFILE_D,		data_service_profile_d)
	__ADD(DECT_EHLC_LRMS,				lrms)
	__ADD(DECT_EHLC_ASYMETRIC_BEARERS,		asymetric_bearers)
	__ADD(DECT_EHLC_EMERGENCY_CALLS,		emergency_calls)
	__ADD(DECT_EHLC_TPUI_LOCATION_REGISTRATION,	tpui_location_registration)
	__ADD(DECT_EHLC_GPS_SYNCHRONIZED,		gps_synchronized)
	__ADD(DECT_EHLC_ISDN_INTERMEDIATE_SYSTEM,	isdn_intermediate_system)
	__ADD(DECT_EHLC_RAP_PART_1_PROFILE,		rap_1_profile)
	__ADD(DECT_EHLC_V_24,				v_24)
	__ADD(DECT_EHLC_PPP,				ppp)
	__ADD(DECT_EHLC_IP,				ip)
	__ADD(DECT_EHLC_TOKEN_RING,			token_ring)
	__ADD(DECT_EHLC_ETHERNET,			ethernet)
	__ADD(DECT_EHLC_IP_ROAMING,			ip_roaming)
	__ADD(DECT_EHLC_GENERIC_MEDIA_ENCAPSULATION,	generic_media_encapsulation)
	__ADD(DECT_EHLC_BASIC_ODAP,			basic_odap)
	__ADD(DECT_EHLC_F_MMS_INTERWORKING_PROFILE,	mms_interworking_profile)
};

char *nl_dect_llme_ehlc2str(uint32_t ehlc, char *buf, size_t len)
{
	return __flags2str(ehlc, buf, len, extended_higher_layer_capabilities,
			   ARRAY_SIZE(extended_higher_layer_capabilities));
}

uint32_t nl_dect_llme_str2ehlc(const char *str)
{
	return __str2flags(str, extended_higher_layer_capabilities,
			   ARRAY_SIZE(extended_higher_layer_capabilities));
}

static struct trans_tbl extended_fixed_part_capabilities2[] = {
	__ADD(DECT_EFPC2_NO_EMISSION_CARRIER,		no_emission_carrier)
	__ADD(DECT_EFPC2_GF,				gf_channel)
	__ADD(DECT_EFPC2_SI_PF,				si_pf_channel)
	__ADD(DECT_EFPC2_IP_F,				ip_f_channel)
	__ADD(DECT_EFPC2_LONG_SLOT_J672,		long_slot_j672)
	__ADD(DECT_EFPC2_LONG_SLOT_J640,		long_slot_j640)
};

char *nl_dect_llme_efpc22str(uint16_t efpc2, char *buf, size_t len)
{
	return __flags2str(efpc2, buf, len, extended_fixed_part_capabilities2,
			   ARRAY_SIZE(extended_fixed_part_capabilities2));
}

uint16_t nl_dect_llme_str2efpc2(const char *str)
{
	return __str2flags(str, extended_fixed_part_capabilities2,
			   ARRAY_SIZE(extended_fixed_part_capabilities2));
}

static struct trans_tbl extended_higher_layer_capabilities2[] = {
	__ADD(DECT_EHLC2_NG_DECT_PERMANENT_CLIR,	permanent_clir)
	__ADD(DECT_EHLC2_NG_DECT_MULTIPLE_CALLS,	multiple_calls)
	__ADD(DECT_EHLC2_NG_DECT_MULTIPLE_LINES,	multiple_lines)
	__ADD(DECT_EHLC2_EASY_PAIRING,			easy_pairing)
	__ADD(DECT_EHLC2_LIST_ACCESS_FEATURES,		list_access_features)
	__ADD(DECT_EHLC2_NO_EMISSION_MODE,		no_emission_mode)
	__ADD(DECT_EHLC2_NG_DECT_CALL_DEFLECTION,	call_deflection)
	__ADD(DECT_EHLC2_NG_DECT_INTRUSION_CALL,	intrusion_call)
	__ADD(DECT_EHLC2_NG_DECT_CONFERENCE_CALL,	conference_call)
	__ADD(DECT_EHLC2_NG_DECT_PARALLEL_CALLS,	parallel_calls)
	__ADD(DECT_EHLC2_NG_DECT_CALL_TRANSFER,		call_transfer)
	__ADD(DECT_EHLC2_NG_DECT_EXTENDED_WIDEBAND,	extended_wideband)
	__ADD(DECT_EHLC2_PACKET_DATA_CATEGORY_MASK,	packet_data)
	__ADD(DECT_EHLC2_NG_DECT_WIDEBAND,		wideband)
};

char *nl_dect_llme_ehlc22str(uint32_t ehlc2, char *buf, size_t len)
{
	return __flags2str(ehlc2, buf, len, extended_higher_layer_capabilities2,
			   ARRAY_SIZE(extended_higher_layer_capabilities2));
}

uint32_t nl_dect_llme_str22ehlc(const char *str)
{
	return __str2flags(str, extended_higher_layer_capabilities2,
			   ARRAY_SIZE(extended_higher_layer_capabilities2));
}


static void nl_dect_llme_mac_info_dump(const struct nl_dect_llme_msg *lmsg,
				       struct nl_dump_params *p)
{
	const struct nl_dect_llme_mac_info *mi = mac_info(lmsg);
	char buf[256];

	if (lmsg->ce_mask & MAC_INFO_ATTR_PARI) {
		nl_dump(p, "\n\tARI: ");
		nl_dect_dump_ari(&mi->mi_pari, p);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_RPN)
		nl_dump(p, " RPN: %x", mi->mi_rpn);
	if (lmsg->ce_mask & MAC_INFO_ATTR_RSSI)
		nl_dump(p, " signal level: %.2fdBm", nl_dect_rssi_to_dbm(mi->mi_rssi));
	if (lmsg->ce_mask & MAC_INFO_ATTR_FPC && mi->mi_fpc) {
		nl_dect_llme_fpc2str(mi->mi_fpc, buf, sizeof(buf));
		nl_dump(p, "\n\tMAC layer capabilities: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_EFPC && mi->mi_efpc) {
		nl_dect_llme_efpc2str(mi->mi_efpc, buf, sizeof(buf));
		nl_dump(p, "\n\tExtended MAC layer capabilities: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_EFPC2 && mi->mi_efpc2) {
		nl_dect_llme_efpc22str(mi->mi_efpc2, buf, sizeof(buf));
		nl_dump(p, "\n\tExtended MAC layer capabilities 2: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_HLC && mi->mi_hlc) {
		nl_dect_llme_hlc2str(mi->mi_hlc, buf, sizeof(buf));
		nl_dump(p, "\n\tHigher layer capabilities: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_EHLC && mi->mi_ehlc) {
		nl_dect_llme_ehlc2str(mi->mi_ehlc, buf, sizeof(buf));
		nl_dump(p, "\n\tExtended higher layer capabilities: %s", buf);
	}
	if (lmsg->ce_mask & MAC_INFO_ATTR_EHLC2 && mi->mi_ehlc2) {
		nl_dect_llme_ehlc22str(mi->mi_ehlc2, buf, sizeof(buf));
		nl_dump(p, "\n\tExtended higher layer capabilities 2: %s", buf);
	}
	nl_dump(p, "\n");
}


static struct nla_policy nl_dect_mac_info_policy[DECTA_MAC_INFO_MAX + 1] =  {
	[DECTA_MAC_INFO_PARI]		= { .type = NLA_NESTED },
	[DECTA_MAC_INFO_RPN]		= { .type = NLA_U8 },
	[DECTA_MAC_INFO_RSSI]		= { .type = NLA_U8 },
	[DECTA_MAC_INFO_SARI_LIST]	= { .type = NLA_NESTED },
	[DECTA_MAC_INFO_FPC]		= { .type = NLA_U32 },
	[DECTA_MAC_INFO_HLC]		= { .type = NLA_U16 },
	[DECTA_MAC_INFO_EFPC]		= { .type = NLA_U16 },
	[DECTA_MAC_INFO_EHLC]		= { .type = NLA_U32 },
	[DECTA_MAC_INFO_EFPC2]		= { .type = NLA_U16 },
	[DECTA_MAC_INFO_EHLC2]		= { .type = NLA_U32 },
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
	if (tb[DECTA_MAC_INFO_EFPC] != NULL)
		nl_dect_llme_mac_info_set_efpc(lmsg, nla_get_u16(tb[DECTA_MAC_INFO_EFPC]));
	if (tb[DECTA_MAC_INFO_EHLC] != NULL)
		nl_dect_llme_mac_info_set_ehlc(lmsg, nla_get_u32(tb[DECTA_MAC_INFO_EHLC]));
	if (tb[DECTA_MAC_INFO_EFPC2] != NULL)
		nl_dect_llme_mac_info_set_efpc2(lmsg, nla_get_u16(tb[DECTA_MAC_INFO_EFPC2]));
	if (tb[DECTA_MAC_INFO_EHLC2] != NULL)
		nl_dect_llme_mac_info_set_ehlc2(lmsg, nla_get_u32(tb[DECTA_MAC_INFO_EHLC2]));
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
	if (lmsg->ce_mask & MAC_INFO_ATTR_HLC)
		NLA_PUT_U16(msg, DECTA_MAC_INFO_HLC, mi->mi_hlc);
	if (lmsg->ce_mask & MAC_INFO_ATTR_EFPC)
		NLA_PUT_U16(msg, DECTA_MAC_INFO_EFPC, mi->mi_efpc);
	if (lmsg->ce_mask & MAC_INFO_ATTR_EHLC)
		NLA_PUT_U32(msg, DECTA_MAC_INFO_EHLC, mi->mi_ehlc);
	if (lmsg->ce_mask & MAC_INFO_ATTR_EFPC2)
		NLA_PUT_U16(msg, DECTA_MAC_INFO_EFPC2, mi->mi_efpc2);
	if (lmsg->ce_mask & MAC_INFO_ATTR_EHLC2)
		NLA_PUT_U32(msg, DECTA_MAC_INFO_EHLC2, mi->mi_ehlc2);
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

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
	[DECT_LLME_MAC_RFP_PRELOAD] = {
		.policy		= nl_dect_mac_info_policy,
		.maxtype	= DECTA_MAC_INFO_MAX,
		.parse		= nl_dect_llme_mac_info_parse,
		.build		= nl_dect_llme_mac_info_build,
		.dump		= nl_dect_llme_mac_info_dump,
	},
};

static void llme_msg_dump(struct nl_object *obj, struct nl_dump_params *p)
{
	struct nl_dect_llme_msg *lmsg = nl_object_priv(obj);
	const struct nl_dect_llme_link *link;
	char buf1[64], buf2[64];

	nl_dect_llme_msgtype2str(lmsg->lm_type, buf1, sizeof(buf1));
	nl_dect_llme_op2str(lmsg->lm_op, buf2, sizeof(buf2));
	nl_dump(p, "%s-%s: ", buf1, buf2);

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
