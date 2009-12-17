#include "netlink/cli/utils.h"

static void obj_input(struct nl_object *obj, void *arg)
{
	struct nl_dump_params dp = {
		.dp_type	= NL_DUMP_LINE,
		.dp_fd		= stdout,
	};
	nl_object_dump(obj, &dp);
}

static int event_input(struct nl_msg *msg, void *arg)
{
	if (nl_msg_parse(msg, &obj_input, NULL) < 0)
		fprintf(stderr, "Unknown message type\n");
	return NL_STOP;
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *cluster_cache;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_DECT);
	if (nl_dect_cluster_alloc_cache(sock, &cluster_cache))
		exit(1);
	nl_cache_mngt_provide(cluster_cache);

	nl_socket_add_membership(sock, DECTNLGRP_LLME);
	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, event_input, NULL);
	while (1)
		nl_recvmsgs_default(sock);
	return 0;
}

