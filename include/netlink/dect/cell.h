#ifndef NETLINK_DECT_CELL_H
#define NETLINK_DECT_CELL_H

#include <stdbool.h>

struct nl_dect_cell;
struct nl_dect_ari;

extern struct nl_object_ops nl_dect_cell_obj_ops;

extern struct nl_dect_cell *	nl_dect_cell_alloc(void);
extern void			nl_dect_cell_get(struct nl_dect_cell *);
extern void			nl_dect_cell_put(struct nl_dect_cell *);

extern void			nl_dect_cell_set_index(struct nl_dect_cell *, int);
extern bool			nl_dect_cell_test_index(const struct nl_dect_cell *);
extern int			nl_dect_cell_get_index(const struct nl_dect_cell *);

extern void			nl_dect_cell_set_name(struct nl_dect_cell *, const char *);
extern bool			nl_dect_cell_test_name(const struct nl_dect_cell *);
extern const char *		nl_dect_cell_get_name(const struct nl_dect_cell *);

extern void			nl_dect_cell_set_flags(struct nl_dect_cell *, uint32_t);
extern bool			nl_dect_cell_test_flags(const struct nl_dect_cell *);
extern uint32_t			nl_dect_cell_get_flags(const struct nl_dect_cell *);

extern void			nl_dect_cell_set_transceiver(struct nl_dect_cell *,
							     unsigned int,
							     const char *);
extern bool			nl_dect_cell_test_transceiver(const struct nl_dect_cell *);
extern const char *		nl_dect_cell_get_transceiver(const struct nl_dect_cell *,
       							     unsigned int);

extern void			nl_dect_cell_set_link(struct nl_dect_cell *, int);
extern bool			nl_dect_cell_test_link(const struct nl_dect_cell *);
extern int			nl_dect_cell_get_link(const struct nl_dect_cell *);

extern int			nl_dect_cell_alloc_cache(struct nl_sock *,
							 struct nl_cache **);

extern int			nl_dect_cell_build_msg(struct nl_msg *,
						       struct nl_dect_cell *);

extern int			nl_dect_cell_build_add_request(struct nl_dect_cell *,
							      int, struct nl_msg **);
extern int			nl_dect_cell_add(struct nl_sock *,
						 struct nl_dect_cell *, int);

extern int			nl_dect_cell_build_del_request(struct nl_dect_cell *,
							       int, struct nl_msg **);
extern int			nl_dect_cell_delete(struct nl_sock *,
						    struct nl_dect_cell *, int);

extern char *			nl_dect_cell_i2name(struct nl_cache *, int, char *,
						    size_t);
extern int			nl_dect_cell_name2i(struct nl_cache *, const char *);

extern char *			nl_dect_cell_flags2str(uint32_t, char *, size_t);
extern uint32_t			nl_dect_cell_str2flags(const char *);

#endif /* NETLINK_DECT_CELL_H */
