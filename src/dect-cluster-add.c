#include "netlink/cli/utils.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_dect_cluster *cl;
	struct nl_dect_ari *pari;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	int err;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_DECT);
	cl = nl_dect_cluster_alloc();
	pari = (void *)nl_dect_cluster_get_pari(cl);

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_NAME = 257,
			ARG_MODE,
			ARG_CLASS,
			ARG_EMC,
			ARG_EIC,
			ARG_POC,
			ARG_GOP,
			ARG_FIL,
			ARG_FPS,
			ARG_FPN,
		};
		static struct option long_opts[] = {
			{ "name",		1, 0, ARG_NAME },
			{ "mode",		1, 0, ARG_MODE },
			{ "class",		1, 0, ARG_CLASS },
			{ "emc",		1, 0, ARG_EMC },
			{ "eic",		1, 0, ARG_EIC },
			{ "poc",		1, 0, ARG_POC },
			{ "gop",		1, 0, ARG_GOP },
			{ "fil",		1, 0, ARG_FIL },
			{ "fps",		1, 0, ARG_FPS },
			{ "fpn",		1, 0, ARG_FPN },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "qhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'v': nl_cli_print_version(); break;
		case ARG_NAME:
			nl_dect_cluster_set_name(cl, strdup(optarg));
			break;
		case ARG_MODE:
			nl_dect_cluster_set_mode(cl, nl_dect_cluster_str2mode(optarg));
			break;
		case ARG_CLASS:
			nl_dect_ari_set_class(pari, nl_dect_ari_str2class(optarg));
			break;
		case ARG_EMC:
			nl_dect_ari_set_emc(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_EIC:
			nl_dect_ari_set_eic(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_POC:
			nl_dect_ari_set_poc(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_GOP:
			nl_dect_ari_set_gop(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_FIL:
			nl_dect_ari_set_fil(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_FPS:
			nl_dect_ari_set_fps(pari, strtoul(optarg, NULL, 16));
			break;
		case ARG_FPN:
			nl_dect_ari_set_fpn(pari, strtoul(optarg, NULL, 16));
			break;
		}
	}

	nl_dect_cluster_set_pari(cl, pari);
	err = nl_dect_cluster_add(sock, cl, 0);
	if (err < 0)
		nl_cli_fatal(err, "Unable to add cluster: %s", nl_geterror(err));

	printf("Added: ");
	nl_object_dump(OBJ_CAST(cl), &params);
	return 0;
}

