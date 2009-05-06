#include "utils.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_dect_cell *cell;
	struct nl_cache *cluster_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	int err;

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_DECT);

	if (nl_dect_cluster_alloc_cache(sock, &cluster_cache))
		exit(1);
	nl_cache_mngt_provide(cluster_cache);

	cell = nl_dect_cell_alloc();
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_CELL = 257,
			ARG_CLUSTER,
			ARG_TRANSCEIVER,
		};
		static struct option long_opts[] = {
			{ "cell",		1, 0, ARG_CELL },
			{ "cluster",		1, 0, ARG_CLUSTER },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "qhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'v': nlt_print_version(); break;
		case ARG_CELL:
			nl_dect_cell_set_name(cell, optarg);
			break;
		case ARG_CLUSTER:
			nl_dect_cell_set_link(cell,
					nl_dect_cluster_name2i(cluster_cache, optarg));
			break;
		}
	}

	err = nl_dect_cell_delete(sock, cell, 0);
	if (err < 0)
		fatal(err, "Unable to delete cell: %s", nl_geterror(err));

	printf("Deleted: ");
	nl_object_dump(OBJ_CAST(cell), &params);
	return 0;
}

