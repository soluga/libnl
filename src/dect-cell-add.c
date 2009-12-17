#include "netlink/cli/utils.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_dect_cell *cell;
	struct nl_cache *cluster_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	uint8_t cli;
	int err;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_DECT);

	if (nl_dect_cluster_alloc_cache(sock, &cluster_cache))
		exit(1);
	nl_cache_mngt_provide(cluster_cache);

	cell = nl_dect_cell_alloc();
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_NAME = 256,
			ARG_FLAGS,
			ARG_CLUSTER,
		};
		static struct option long_opts[] = {
			{ "name",		1, 0, ARG_NAME },
			{ "flags",		1, 0, ARG_FLAGS },
			{ "cluster",		1, 0, ARG_CLUSTER },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "qhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'v': nl_cli_print_version(); break;
		case ARG_NAME:
			nl_dect_cell_set_name(cell, optarg);
			break;
		case ARG_FLAGS:
			nl_dect_cell_set_flags(cell, nl_dect_cell_str2flags(optarg));
			break;
		case ARG_CLUSTER:
			if (isdigit(*optarg))
				cli = strtoul(optarg, NULL, 0);
			else
				cli = nl_dect_cluster_name2i(cluster_cache, optarg);
			nl_dect_cell_set_link(cell, cli);
			break;
		}
	}

	err = nl_dect_cell_add(sock, cell, 0);
	if (err < 0)
		nl_cli_fatal(err, "Unable to add cell: %s", nl_geterror(err));

	printf("Added: ");
	nl_object_dump(OBJ_CAST(cell), &params);
	return 0;
}

