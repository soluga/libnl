#ifndef NETLINK_DECT_CLUSTER_H
#define NETLINK_DECT_CLUSTER_H

#include <stdbool.h>

struct nl_dect_cluster;
struct nl_dect_ari;

extern struct nl_object_ops nl_dect_cluster_obj_ops;

extern struct nl_dect_cluster *	nl_dect_cluster_alloc(void);
extern void			nl_dect_cluster_get(struct nl_dect_cluster *);
extern void			nl_dect_cluster_put(struct nl_dect_cluster *);

extern unsigned int		nl_dect_cluster_get_index(const struct nl_dect_cluster *);

extern void			nl_dect_cluster_set_name(struct nl_dect_cluster *,
							 const char *);
extern bool			nl_dect_cluster_test_name(const struct nl_dect_cluster *);
extern const char *		nl_dect_cluster_get_name(const struct nl_dect_cluster *);

extern void			nl_dect_cluster_set_mode(struct nl_dect_cluster *,
							 uint8_t mode);
extern bool			nl_dect_cluster_test_mode(const struct nl_dect_cluster *);
extern uint8_t			nl_dect_cluster_get_mode(const struct nl_dect_cluster *);

extern void			nl_dect_cluster_set_pari(struct nl_dect_cluster *,
							 const struct nl_dect_ari *);
extern bool			nl_dect_cluster_test_pari(const struct nl_dect_cluster *);
extern const struct nl_dect_ari *nl_dect_cluster_get_pari(const struct nl_dect_cluster *);

extern char *			nl_dect_cluster_mode2str(enum dect_cluster_modes,
							 char *, size_t);
extern enum dect_cluster_modes	nl_dect_cluster_str2mode(const char *);

extern int			nl_dect_cluster_alloc_cache(struct nl_sock *,
							    struct nl_cache **);

extern int			nl_dect_cluster_build_msg(struct nl_msg *,
							  struct nl_dect_cluster *);

extern int			nl_dect_cluster_build_add_request(struct nl_dect_cluster *,
								  int, struct nl_msg **);
extern int			nl_dect_cluster_add(struct nl_sock *,
						    struct nl_dect_cluster *, int);

extern int			nl_dect_cluster_build_del_request(struct nl_dect_cluster *,
								  int, struct nl_msg **);
extern int			nl_dect_cluster_delete(struct nl_sock *,
						       struct nl_dect_cluster *, int);

extern int			nl_dect_cluster_build_query_request(struct nl_dect_cluster *,
								    int, struct nl_msg **);
extern int			nl_dect_cluster_query(struct nl_sock *,
						      struct nl_dect_cluster *, int);

extern char *			nl_dect_cluster_i2name(struct nl_cache *, int, char *,
						       size_t);
extern int			nl_dect_cluster_name2i(struct nl_cache *, const char *);

#endif /* NETLINK_DECT_CLUSTER_H */
