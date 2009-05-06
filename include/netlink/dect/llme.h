#ifndef NETLINK_DECT_LLME_H
#define NETLINK_DECT_LLME_H

#include <stdbool.h>

struct nl_dect_llme_msg;
struct nl_dect_ari;

extern struct nl_dect_llme_msg *nl_dect_llme_msg_alloc(void);
extern void			nl_dect_llme_msg_get(struct nl_dect_llme_msg *);
extern void			nl_dect_llme_msg_put(struct nl_dect_llme_msg *);

extern int			nl_dect_llme_build_request(struct nl_dect_llme_msg *,
							   struct nl_msg **);
extern int			nl_dect_llme_request(struct nl_sock *,
						     struct nl_dect_llme_msg *);

extern int			nl_dect_llme_build_response(struct nl_dect_llme_msg *,
							    struct nl_msg **);
extern int			nl_dect_llme_respond(struct nl_sock *, struct nl_dect_llme_msg *);

extern void			nl_dect_llme_msg_set_index(struct nl_dect_llme_msg *, int);
extern void			nl_dect_llme_msg_set_type(struct nl_dect_llme_msg *,
							  enum dect_llme_msg_types);
extern enum dect_llme_msg_types	nl_dect_llme_msg_get_type(const struct nl_dect_llme_msg *);
extern void			nl_dect_llme_msg_set_op(struct nl_dect_llme_msg *,
							enum dect_llme_ops);
extern enum dect_llme_ops	nl_dect_llme_msg_get_op(const struct nl_dect_llme_msg *);

extern char *			nl_dect_llme_msgtype2str(enum dect_llme_msg_types,
							 char *, size_t);
extern enum dect_llme_msg_types	nl_dect_llme_str2msgtype(const char *);

extern char *			nl_dect_llme_op2str(enum dect_llme_ops,
						    char *, size_t);
extern enum dect_llme_ops	nl_dect_llme_str2op(const char *);


extern void			nl_dect_llme_mac_info_set_pari(struct nl_dect_llme_msg *lmsg,
							       const struct nl_dect_ari *);
extern const struct nl_dect_ari *nl_dect_llme_mac_info_get_pari(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_info_set_rpn(struct nl_dect_llme_msg *,
							      uint8_t);
extern uint8_t			nl_dect_llme_mac_info_get_rpn(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_info_set_rssi(struct nl_dect_llme_msg *,
							       uint8_t);
extern uint8_t			nl_dect_llme_mac_info_get_rssi(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_info_set_fpc(struct nl_dect_llme_msg *,
							      uint32_t);
extern uint32_t			nl_dect_llme_mac_info_get_fpc(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_info_set_hlc(struct nl_dect_llme_msg *,
							      uint16_t);
extern uint16_t			nl_dect_llme_mac_info_get_hlc(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_info_set_ehlc(struct nl_dect_llme_msg *,
							       uint16_t);
extern uint16_t			nl_dect_llme_mac_info_get_ehlc(const struct nl_dect_llme_msg *);

extern char *			nl_dect_llme_fpc2str(uint32_t, char *, size_t);
extern uint32_t			nl_dect_llme_str2fpc(const char *);

extern char *			nl_dect_llme_hlc2str(uint16_t, char *, size_t);
extern uint16_t			nl_dect_llme_str2hlc(const char *);

extern char *			nl_dect_llme_ehlc2str(uint16_t, char *, size_t);
extern uint16_t			nl_dect_llme_str2ehlc(const char *);

#if 0
extern void			nl_dect_llme_mac_con_set_mcei(struct nl_dect_llme_msg *,
							   uint32_t);
extern uint32_t			nl_dect_llme_mac_con_get_mcei(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_con_set_ari(struct nl_dect_llme_msg *,
							  const struct nl_dect_ari *);
extern const struct nl_dect_ari *	nl_dect_llme_mac_con_get_ari(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_con_set_pmid(struct nl_dect_llme_msg *,
							   uint32_t);
extern uint32_t			nl_dect_llme_mac_con_get_pmid(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_con_set_type(struct nl_dect_llme_msg *,
							   enum nl_dect_mac_con_types);
extern enum nl_dect_mac_con_types	nl_dect_llme_mac_con_get_type(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_con_set_ecn(struct nl_dect_llme_msg *,
							  uint8_t);
extern uint8_t			nl_dect_llme_mac_con_get_ecn(const struct nl_dect_llme_msg *);

extern void			nl_dect_llme_mac_con_set_service(struct nl_dect_llme_msg *,
							      enum nl_dect_mac_con_service_types);
extern enum nl_dect_mac_con_service_types nl_dect_llme_mac_con_get_service(const struct nl_dect_llme_msg *);

extern char *			nl_dect_llme_contype2str(enum nl_dect_mac_con_types,
						      char *, size_t);
extern enum nl_dect_mac_con_types	nl_dect_llme_str2contype(const char *);

extern char *			nl_dect_llme_service2str(enum nl_dect_mac_con_service_types,
						      char *, size_t);
extern enum nl_dect_mac_con_service_types nl_dect_llme_str2service(const char *);
#endif

#endif /* NETLINK_DECT_LLME_H */
