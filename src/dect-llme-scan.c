#include "netlink/cli/utils.h"

#define CACHE_SIZE	64

static struct {
	unsigned int		index;
	unsigned int		used;
	struct {
		uint16_t		emc;
		uint32_t		fpn;
		uint8_t			rpn;
	} ids[CACHE_SIZE];
} cache;

static void add_ari(const struct nl_dect_llme_msg *lmsg)
{
	const struct nl_dect_ari *ari = nl_dect_llme_mac_info_get_pari(lmsg);
	unsigned int index = cache.index;

	cache.ids[index].emc = nl_dect_ari_get_emc(ari);
	cache.ids[index].fpn = nl_dect_ari_get_fpn(ari);
	cache.ids[index].rpn = nl_dect_llme_mac_info_get_rpn(lmsg);

	if (++cache.used > CACHE_SIZE)
		cache.used = CACHE_SIZE;
	if (++cache.index == CACHE_SIZE)
		cache.index = 0;
}

static bool lookup_ari(const struct nl_dect_llme_msg *lmsg)
{
	const struct nl_dect_ari *ari = nl_dect_llme_mac_info_get_pari(lmsg);
	unsigned int index;

	for (index = 0; index < cache.used; index++) {
		if (cache.ids[index].emc == nl_dect_ari_get_emc(ari) &&
		    cache.ids[index].fpn == nl_dect_ari_get_fpn(ari) &&
		    cache.ids[index].rpn == nl_dect_llme_mac_info_get_rpn(lmsg))
			return true;
	}
	return false;
}

static void obj_input(struct nl_object *obj, void *arg)
{
	struct nl_dect_llme_msg *lmsg = nl_object_priv(obj);
	struct nl_dump_params dp = {
		.dp_type	= NL_DUMP_LINE,
		.dp_fd		= stdout,
	};
	static unsigned int n;

	if (lookup_ari(lmsg))
		return;
	add_ari(lmsg);

	printf("%u: Station: ", ++n);
	nl_object_dump(obj, &dp);
	printf("\n");
}

static int event_input(struct nl_msg *msg, void *arg)
{
	if (nl_msg_parse(msg, &obj_input, NULL) < 0)
		fprintf(stderr, "Unknown message type\n");
	return NL_OK;
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *cluster_cache;
	struct nl_dect_llme_msg *lmsg;
	struct nl_dect_ari *pari;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	int index;
	int err;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_DECT);
	if (nl_dect_cluster_alloc_cache(sock, &cluster_cache))
		exit(1);
	nl_cache_mngt_provide(cluster_cache);

	lmsg = nl_dect_llme_msg_alloc();
	nl_dect_llme_msg_set_type(lmsg, DECT_LLME_SCAN);

	pari = (void *)nl_dect_llme_mac_info_get_pari(lmsg);

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_CLUSTER = 257,
			ARG_EMC,
			ARG_FPN,
		};
		static struct option long_opts[] = {
			{ "cluster",		1, 0, ARG_CLUSTER },
			{ "emc",		1, 0, ARG_EMC },
			{ "fpn",		1, 0, ARG_FPN },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "qhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'v': nl_cli_print_version(); break;
		case ARG_CLUSTER:
			index = nl_dect_cluster_name2i(cluster_cache, optarg);
			nl_dect_llme_msg_set_index(lmsg, index);
			break;
		case ARG_EMC:
			nl_dect_ari_set_emc(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_FPN:
			nl_dect_ari_set_fpn(pari, strtoul(optarg, NULL, 16));
			break;
		}
	}

	//nl_dect_llme_mac_info_set_pari(lmsg, pari);
	if ((err = nl_dect_llme_request(sock, lmsg)) < 0)
		nl_cli_fatal(err, "Unable to send request: %s", nl_geterror(err));

	printf("Requested: ");
	nl_object_dump(OBJ_CAST(lmsg), &params);

	nl_socket_disable_seq_check(sock);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, event_input, NULL);
	while (1)
		nl_recvmsgs_default(sock);
	return 0;
}

