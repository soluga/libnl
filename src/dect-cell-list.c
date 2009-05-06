#include "utils.h"

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *cell_cache;
	struct nl_cache *cluster_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_DECT);
	if (nl_dect_cluster_alloc_cache(sock, &cluster_cache))
		exit(1);
	nl_cache_mngt_provide(cluster_cache);
	if (nl_dect_cell_alloc_cache(sock, &cell_cache))
		exit(1);

	nl_cache_dump(cell_cache, &params);
	return 0;
}

