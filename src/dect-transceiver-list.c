#include "netlink/cli/utils.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *cell_cache;
	struct nl_cache *transceiver_cache;
	struct nl_dect_transceiver *trx;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_DECT);

	if (nl_dect_cell_alloc_cache(sock, &cell_cache))
		exit(1);
	nl_cache_mngt_provide(cell_cache);

	if (nl_dect_transceiver_alloc_cache(sock, &transceiver_cache))
		exit(1);
	trx = nl_dect_transceiver_alloc();
	if (trx == NULL)
		exit(1);

	for (;;) {
		int c, optidx = 0, cidx;
		enum {
			ARG_NAME	= 257,
			ARG_CELL,
		};
		static struct option long_ops[] = {
			{ "name", 1, 0, ARG_NAME },
			{ "cell", 1, 0, ARG_CELL },
			{}
		};

		c = getopt_long(argc, argv, "n:c:", long_ops, &optidx);
		if (c == -1)
			break;
		switch (c) {
		case ARG_NAME:
			nl_dect_transceiver_set_name(trx, optarg);
			break;
		case ARG_CELL:
			cidx = nl_dect_cell_name2i(cell_cache, optarg);
			if (cidx == 0) {
				fprintf(stderr, "cell %s does not exist\n", optarg);
				exit(1);
			}
			nl_dect_transceiver_set_link(trx, cidx);
			break;
		}
	}

	nl_cache_dump_filter(transceiver_cache, &params, OBJ_CAST(trx));
	return 0;
}

