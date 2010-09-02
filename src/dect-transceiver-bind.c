#include "netlink/cli/utils.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_dect_transceiver *trx;
	struct nl_cache *cell_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	int err;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_DECT);

	if (nl_dect_cell_alloc_cache(sock, &cell_cache))
		exit(1);
	nl_cache_mngt_provide(cell_cache);

	trx = nl_dect_transceiver_alloc();
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_TRANSCEIVER = 257,
			ARG_CELL,
			ARG_UNBIND,
		};
		static struct option long_opts[] = {
			{ "transceiver",	1, 0, ARG_TRANSCEIVER },
			{ "cell",		1, 0, ARG_CELL },
			{ "unbind",		0, 0, ARG_UNBIND },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "qhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'v': nl_cli_print_version(); break;
		case ARG_TRANSCEIVER:
			nl_dect_transceiver_set_name(trx, strdup(optarg));
			break;
		case ARG_CELL:
			nl_dect_transceiver_set_link(trx, nl_dect_cell_name2i(cell_cache, optarg));
			break;
		case ARG_UNBIND:
			nl_dect_transceiver_set_link(trx, -1);
			break;
		}
	}

	err = nl_dect_transceiver_change(sock, trx, 0);
	if (err < 0)
		nl_cli_fatal(err, "Unable to bind to cell: %s", nl_geterror(err));

	printf("Bound: ");
	nl_object_dump(OBJ_CAST(trx), &params);
	return 0;
}

