#ifndef NETLINK_DECT_TRANSCEIVER_H
#define NETLINK_DECT_TRANSCEIVER_H

#include <stdbool.h>

struct nl_dect_transceiver;

extern struct nl_object_ops nl_dect_transceiver_obj_ops;

extern struct nl_dect_transceiver *nl_dect_transceiver_alloc(void);
extern void			nl_dect_transceiver_get(struct nl_dect_transceiver *);
extern void			nl_dect_transceiver_put(struct nl_dect_transceiver *);

extern void			nl_dect_transceiver_set_name(struct nl_dect_transceiver *,
							     const char *);
extern bool			nl_dect_transceiver_test_name(const struct nl_dect_transceiver *);
extern const char *		nl_dect_transceiver_get_name(const struct nl_dect_transceiver *);

extern void			nl_dect_transceiver_set_type(struct nl_dect_transceiver *,
							     const char *);
extern bool			nl_dect_transceiver_test_type(const struct nl_dect_transceiver *);
extern const char *		nl_dect_transceiver_get_type(const struct nl_dect_transceiver *);

extern void			nl_dect_transceiver_set_index(struct nl_dect_transceiver *,
							      int);
extern void			nl_dect_transceiver_set_link(struct nl_dect_transceiver *,
							     uint8_t);

extern void			nl_dect_transceiver_set_band(struct nl_dect_transceiver *,
							     uint8_t);
extern bool			nl_dect_transceiver_test_band(const struct nl_dect_transceiver *);
extern uint8_t			nl_dect_transceiver_get_band(const struct nl_dect_transceiver *);

extern int			nl_dect_transceiver_build_msg(struct nl_msg *,
							      struct nl_dect_transceiver *);
extern int			nl_dect_transceiver_build_change_request(struct nl_dect_transceiver *,
									 int, struct nl_msg **);
extern int			nl_dect_transceiver_change(struct nl_sock *,
							   struct nl_dect_transceiver *, int flags);

extern char *			nl_dect_slot_state2str(uint8_t, char *, size_t);
extern uint8_t			nl_dect_slot_str2state(const char *);

extern int			nl_dect_transceiver_alloc_cache(struct nl_sock *,
								struct nl_cache **);

#endif /* NETLINK_DECT_TRANSCEIVER_H */
