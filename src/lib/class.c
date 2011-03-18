/*
 * src/lib/class.c     CLI Class Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup cli
 * @defgroup cli_class Traffic Classes
 * @{
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/class.h>

struct rtnl_class *nl_cli_class_alloc(void)
{
	struct rtnl_class *class;

	class = rtnl_class_alloc();
	if (!class)
		nl_cli_fatal(ENOMEM, "Unable to allocate class object");

	return class;
}

struct nl_cache *nl_cli_class_alloc_cache(struct nl_sock *sock, int ifindex)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_class_alloc_cache(sock, ifindex, &cache)) < 0)
		nl_cli_fatal(err, "Unable to allocate class cache: %s",
			     nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

void nl_cli_class_parse_kind(struct rtnl_class *class, char *arg)
{
	rtnl_class_set_kind(class, arg);
}

/** @} */
