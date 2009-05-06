/*
 * lib/dect/dect.c	DECT
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/dect/dect.h>

double nl_dect_rssi_to_dbm(uint8_t rssi)
{
	if (rssi == 0)
		return 0;
	return -93 + (rssi * 60.0 / 255);
}
