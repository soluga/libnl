#if 0
#include "utils.h"

static void obj_input(struct nl_object *obj, void *arg)
{
	struct nl_dump_params dp = {
		.dp_type	= NL_DUMP_LINE,
		.dp_fd		= stdout,
	};

	printf("MAC Connection: ");
	nl_object_dump(obj, &dp);
	printf("\n");
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
	struct dect_llme_msg *lmsg;
	struct dect_ari *ari;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	int index;
	int err;

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_DECT);
	if (dect_cluster_alloc_cache(sock, &cluster_cache))
		exit(1);
	nl_cache_mngt_provide(cluster_cache);

	lmsg = dect_llme_msg_alloc();
	dect_llme_msg_set_type(lmsg, DECT_LLME_MAC_CON);

	ari = (void *)dect_llme_mac_con_get_ari(lmsg);

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_CLUSTER = 257,
			ARG_MCEI,
			ARG_PMID,
			ARG_EMC,
			ARG_FPN,
			ARG_FPC,
		};
		static struct option long_opts[] = {
			{ "cluster",		1, 0, ARG_CLUSTER },
			{ "mcei",		1, 0, ARG_MCEI },
			{ "pmid",		1, 0, ARG_PMID },
			{ "emc",		1, 0, ARG_EMC },
			{ "fpn",		1, 0, ARG_FPN },
			{ "fpc",		0, 0, ARG_FPC },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "qhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'v': nlt_print_version(); break;
		case ARG_CLUSTER:
			index = dect_cluster_name2i(cluster_cache, optarg);
			dect_llme_msg_set_index(lmsg, index);
			break;
		case ARG_MCEI:
			dect_llme_mac_con_set_mcei(lmsg, strtoul(optarg, NULL, 16));
			break;
		case ARG_PMID:
			dect_llme_mac_con_set_pmid(lmsg, strtoul(optarg, NULL, 16));
			break;
		case ARG_EMC:
			dect_ari_set_emc(ari, strtoul(optarg, NULL, 16));
			break;
		case ARG_FPN:
			dect_ari_set_fpn(ari, strtoul(optarg, NULL, 16));
			break;
		case ARG_FPC:
			dect_llme_mac_info_set_fpc(lmsg, 0);
			dect_llme_mac_info_set_ehlc(lmsg, 0);
			break;
		}
	}

	//dect_llme_mac_con_set_ari(lmsg, ari);
	if ((err = dect_llme_request(sock, lmsg)) < 0)
		fatal(err, "Unable to send request: %s", nl_geterror(err));

	printf("Requested: ");
	nl_object_dump(OBJ_CAST(lmsg), &params);

	nl_socket_add_membership(sock, DECTNLGRP_LLME);
	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, event_input, NULL);
	while (1)
		nl_recvmsgs_default(sock);
	return 0;
}
#endif
int main() {}
