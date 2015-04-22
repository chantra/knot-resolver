/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <netinet/in.h>
#include <libknot/dname.h>

#include "lib/generic/map.h"

/** 
  * Special values for nameserver score.
  * All positive values mean valid nameserver.
  */
enum kr_ns_score {
	KR_NS_INVALID = 0,
	KR_NS_VALID   = 1
};

/**
 * Name server representation.
 * Contains extra information about the name server, e.g. score
 * or other metadata.
 */
struct kr_nsrep
{
	unsigned score;                  /**< Server score */
	const knot_dname_t *name;        /**< Server name */
	union {
		struct sockaddr ip;
		struct sockaddr_in ip4;
		struct sockaddr_in6 ip6;
	} addr;                          /**< Server address */
};

/** @internal Address bytes for given family. */
#define kr_nsrep_inaddr(addr) \
	((addr).ip.sa_family == AF_INET ? (void *)&((addr).ip4.sin_addr) : (void *)&((addr).ip6.sin6_addr))
/** @internal Address length for given family. */
#define kr_nsrep_inaddr_len(addr) \
	((addr).ip.sa_family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr))

/**
 * Elect best nameserver/address pair from the nsset.
 * @param  ns    updated NS representation
 * @param  nsset NS set to choose from
 * @return       score, see enum kr_ns_score
 */
int kr_nsrep_elect(struct kr_nsrep *ns, map_t *nsset);