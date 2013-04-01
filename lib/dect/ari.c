#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/dect/ari.h>
#include <linux/dect_netlink.h>

#define ARI_ATTR_CLASS	0x01
#define ARI_ATTR_FPN	0x02
#define ARI_ATTR_FPS	0x03
#define ARI_ATTR_EMC	0x04
#define ARI_ATTR_EIC	0x05
#define ARI_ATTR_POC	0x06
#define ARI_ATTR_GOP	0x07
#define ARI_ATTR_FIL	0x08

static struct nla_policy nl_dect_ari_policy[DECTA_ARI_MAX + 1] = {
	[DECTA_ARI_CLASS]	= { .type = NLA_U8 },
	[DECTA_ARI_FPN]		= { .type = NLA_U32 },
	[DECTA_ARI_FPS]		= { .type = NLA_U32 },
	[DECTA_ARI_EMC]		= { .type = NLA_U16 },
	[DECTA_ARI_EIC]		= { .type = NLA_U16 },
	[DECTA_ARI_POC]		= { .type = NLA_U16 },
	[DECTA_ARI_GOP]		= { .type = NLA_U32 },
	[DECTA_ARI_FIL]		= { .type = NLA_U32 },
};

int nl_dect_parse_ari(struct nl_dect_ari *ari, struct nlattr *nla)
{
	struct nlattr *tb[DECTA_ARI_MAX + 1];
	int err;

	err = nla_parse_nested(tb, DECTA_ARI_MAX, nla, nl_dect_ari_policy);
	if (err < 0)
		return err;

	if (tb[DECTA_ARI_CLASS] == NULL)
		return -NLE_INVAL;

	memset(ari, 0, sizeof(ari));
	ari->ari_class = nla_get_u8(tb[DECTA_ARI_CLASS]);
	if (tb[DECTA_ARI_FPN] != NULL)
		ari->ari_fpn = nla_get_u32(tb[DECTA_ARI_FPN]);

	switch (ari->ari_class) {
	case DECT_ARC_A:
		if (tb[DECTA_ARI_EMC] != NULL)
			ari->ari_u.emc = nla_get_u16(tb[DECTA_ARI_EMC]);
		break;
	case DECT_ARC_B:
		if (tb[DECTA_ARI_EIC] != NULL)
			ari->ari_u.eic = nla_get_u16(tb[DECTA_ARI_EIC]);
		if (tb[DECTA_ARI_FPS] != NULL)
			ari->ari_fps = nla_get_u32(tb[DECTA_ARI_FPS]);
		break;
	case DECT_ARC_C:
		if (tb[DECTA_ARI_POC] != NULL)
			ari->ari_u.poc = nla_get_u16(tb[DECTA_ARI_POC]);
		if (tb[DECTA_ARI_FPS] != NULL)
			ari->ari_fps = nla_get_u32(tb[DECTA_ARI_FPS]);
		break;
	case DECT_ARC_D:
		if (tb[DECTA_ARI_GOP] != NULL)
			ari->ari_u.gop = nla_get_u32(tb[DECTA_ARI_GOP]);
		break;
	case DECT_ARC_E:
		if (tb[DECTA_ARI_FIL] != NULL)
			ari->ari_u.fil = nla_get_u16(tb[DECTA_ARI_FIL]);
		break;
	default:
		return -NLE_INVAL;
	}

	return 0;
}

int nl_dect_fill_ari(struct nl_msg *msg, const struct nl_dect_ari *ari, int attr)
{
	struct nlattr *nla;

	nla = nla_nest_start(msg, attr);
	if (nla == NULL)
		goto nla_put_failure;

	NLA_PUT_U8(msg, DECTA_ARI_CLASS, ari->ari_class);
	NLA_PUT_U32(msg, DECTA_ARI_FPN, ari->ari_fpn);

	switch (ari->ari_class) {
	case DECT_ARC_A:
		NLA_PUT_U16(msg, DECTA_ARI_EMC, ari->ari_u.emc);
		break;
	case DECT_ARC_B:
		NLA_PUT_U16(msg, DECTA_ARI_EIC, ari->ari_u.eic);
		NLA_PUT_U32(msg, DECTA_ARI_FPS, ari->ari_fps);
		break;
	case DECT_ARC_C:
		NLA_PUT_U16(msg, DECTA_ARI_POC, ari->ari_u.poc);
		NLA_PUT_U32(msg, DECTA_ARI_FPS, ari->ari_fps);
		break;
	case DECT_ARC_D:
		NLA_PUT_U32(msg, DECTA_ARI_GOP, ari->ari_u.gop);
		break;
	case DECT_ARC_E:
		NLA_PUT_U16(msg, DECTA_ARI_FIL, ari->ari_u.fil);
		break;
	}
	nla_nest_end(msg, nla);
	return 0;

nla_put_failure:
	return -NLE_MSGSIZE;
}

void nl_dect_dump_ari(const struct nl_dect_ari *ari, struct nl_dump_params *p)
{
	nl_dump(p, "class %c ", 'A' + ari->ari_class);

	switch (ari->ari_class) {
	case DECT_ARC_A:
		nl_dump(p, "(residential) EMC: %.4x FPN: %.5x",
			ari->ari_u.emc, ari->ari_fpn);
		break;
	case DECT_ARC_B:
		nl_dump(p, "(private multiple cell) EIC: %.4x FPN: %.2x FPS: %x",
			ari->ari_u.eic, ari->ari_fpn, ari->ari_fps);
		break;
	case DECT_ARC_C:
		nl_dump(p, "(public) POC: %.4x FPN: %.2x FPS: %x",
			ari->ari_u.poc, ari->ari_fpn, ari->ari_fps);
		break;
	case DECT_ARC_D:
		nl_dump(p, "(public GSM) GOP: %.5x FPN: %.2x",
			ari->ari_u.gop, ari->ari_fpn);
		break;
	case DECT_ARC_E:
		nl_dump(p, "(PP to PP) FIL: %.4x FPN: %.3x",
			ari->ari_u.fil, ari->ari_fpn);
	}

}

static struct trans_tbl ari_classes[] = {
	__ADD(DECT_ARC_A,		a)
	__ADD(DECT_ARC_B,		b)
	__ADD(DECT_ARC_C,		c)
	__ADD(DECT_ARC_D,		d)
	__ADD(DECT_ARC_E,		e)
};

const char *nl_dect_ari_class2str(enum dect_ari_classes class, char *buf, size_t len)
{
	return __type2str(class, buf, len, ari_classes, ARRAY_SIZE(ari_classes));
}

enum dect_ari_classes nl_dect_ari_str2class(const char *str)
{
	return __str2type(str, ari_classes, ARRAY_SIZE(ari_classes));
}

void nl_dect_ari_set_class(struct nl_dect_ari *ari, enum dect_ari_classes class)
{
	ari->ari_flags |= ARI_ATTR_CLASS;
	ari->ari_class = class;
}

enum dect_ari_classes nl_dect_ari_get_class(const struct nl_dect_ari *ari)
{
	return ari->ari_class;
}

void nl_dect_ari_set_fpn(struct nl_dect_ari *ari, uint32_t fpn)
{
	ari->ari_flags |= ARI_ATTR_FPN;
	ari->ari_fpn = fpn;
}

uint32_t nl_dect_ari_get_fpn(const struct nl_dect_ari *ari)
{
	return ari->ari_fpn;
}

void nl_dect_ari_set_fps(struct nl_dect_ari *ari, uint32_t fps)
{
	ari->ari_flags |= ARI_ATTR_FPS;
	ari->ari_fps = fps;
}

uint32_t nl_dect_ari_get_fps(const struct nl_dect_ari *ari)
{
	return ari->ari_fps;
}

void nl_dect_ari_set_emc(struct nl_dect_ari *ari, uint16_t emc)
{
	ari->ari_flags |= ARI_ATTR_EMC;
	ari->ari_u.emc = emc;
}

uint16_t nl_dect_ari_get_emc(const struct nl_dect_ari *ari)
{
	return ari->ari_u.emc;
}

void nl_dect_ari_set_eic(struct nl_dect_ari *ari, uint16_t eic)
{
	ari->ari_flags |= ARI_ATTR_EIC;
	ari->ari_u.eic = eic;
}

uint16_t nl_dect_ari_get_eic(const struct nl_dect_ari *ari)
{
	return ari->ari_u.eic;
}

void nl_dect_ari_set_poc(struct nl_dect_ari *ari, uint16_t poc)
{
	ari->ari_flags |= ARI_ATTR_POC;
	ari->ari_u.poc = poc;
}

uint16_t nl_dect_ari_get_poc(const struct nl_dect_ari *ari)
{
	return ari->ari_u.poc;
}

void nl_dect_ari_set_gop(struct nl_dect_ari *ari, uint32_t gop)
{
	ari->ari_flags |= ARI_ATTR_GOP;
	ari->ari_u.gop = gop;
}

uint32_t nl_dect_ari_get_gop(const struct nl_dect_ari *ari)
{
	return ari->ari_u.gop;
}

void nl_dect_ari_set_fil(struct nl_dect_ari *ari, uint16_t fil)
{
	ari->ari_flags |= ARI_ATTR_FIL;
	ari->ari_u.fil = fil;
}

uint16_t nl_dect_ari_get_fil(const struct nl_dect_ari *ari)
{
	return ari->ari_u.fil;
}
