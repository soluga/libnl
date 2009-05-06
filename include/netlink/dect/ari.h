#ifndef NETLINK_DECT_ARI_H
#define NETLINK_DECT_ARI_H

#include <stdbool.h>

struct nl_dect_ari;

extern int			nl_dect_parse_ari(struct nl_dect_ari *,
						  struct nlattr *);
extern int			nl_dect_fill_ari(struct nl_msg *,
						 const struct nl_dect_ari *,
						 int);
extern void			nl_dect_dump_ari(const struct nl_dect_ari *,
						 struct nl_dump_params *);

extern void 			nl_dect_ari_set_class(struct nl_dect_ari *,
						      enum dect_ari_classes);
extern enum dect_ari_classes 	nl_dect_ari_get_class(const struct nl_dect_ari *);

extern void			nl_dect_ari_set_fpn(struct nl_dect_ari *, uint32_t);
extern uint32_t			nl_dect_ari_get_fpn(const struct nl_dect_ari *);
extern void			nl_dect_ari_set_fps(struct nl_dect_ari *, uint32_t);
extern uint32_t			nl_dect_ari_get_fps(const struct nl_dect_ari *);
extern void			nl_dect_ari_set_emc(struct nl_dect_ari *, uint16_t);
extern uint16_t			nl_dect_ari_get_emc(const struct nl_dect_ari *);
extern void			nl_dect_ari_set_eic(struct nl_dect_ari *, uint16_t);
extern uint16_t			nl_dect_ari_get_eic(const struct nl_dect_ari *);
extern void			nl_dect_ari_set_poc(struct nl_dect_ari *, uint16_t);
extern uint16_t			nl_dect_ari_get_poc(const struct nl_dect_ari *);
extern void			nl_dect_ari_set_gop(struct nl_dect_ari *, uint32_t);
extern uint32_t			nl_dect_ari_get_gop(const struct nl_dect_ari *);
extern void			nl_dect_ari_set_fil(struct nl_dect_ari *, uint16_t);
extern uint16_t			nl_dect_ari_get_fil(const struct nl_dect_ari *);

#endif /* NETLINK_DECT_ARI_H */
