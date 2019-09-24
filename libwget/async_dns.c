/*
 * Copyright(c) 2019 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libwget.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <sys/select.h>
#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include <wget.h>
#include "private.h"

#define SERVERS    "1.0.0.1,8.8.8.8" /* DNS server to use (Cloudflare & Google) */

#define MAXWAITING 200 // Max. number of parallel DNS queries (default value)
#define TIMEOUT 2000 // Max. number of ms for first try (default value)
#define MAXTRIES 3 // Max. number of tries per domain (default value)

//TODO: Check that wget2 compiles if c-ares is not installed

//TODO: Document this file like the others

//TODO: create DNS statistics (if needed, see --stats-dns)

//TODO: Allow custom servers, see https://github.com/Abss0x7tbh/bass fro a huge list of resolvers
//      Using many resolvers reduces the chance of being blacklisted by the provider.

struct wget_async_dns_st {
	int
		nwaiting, // number of current pending parallel DNS queries
		maxwaiting; // max. number of parallel DNS queries
	wget_dns
		*dns; // DNS data (including cache). see libwget/dns.c
	ares_channel
		channel; // ares channel, to resolve DNS
};

static void callback(void *arg, int status, int timeouts, struct hostent *host)
{
	wget_async_dns *cur = (wget_async_dns *) arg;
	cur->nwaiting--;

	if (!host || status != ARES_SUCCESS){
		debug_printf("Failed to lookup 1 domain: %s\n", ares_strerror(status));
		return;
	}

	char ip[INET_ADDRSTRLEN];
	if (host->h_addr_list[0] && host->h_name) {
		inet_ntop(host->h_addrtype, host->h_addr_list[0], ip, sizeof(ip));
		wget_dns_cache_ip(cur->dns, ip, host->h_name, 80);
		wget_dns_cache_ip(cur->dns, ip, host->h_name, 443);
		debug_printf("%s: %s\n", host->h_name, ip);
	}
}

static void wait_ares(ares_channel channel)
{
	struct timeval *tvp, tv;
	fd_set read_fds, write_fds;
	int nfds;

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	nfds = ares_fds(channel, &read_fds, &write_fds);

	if (nfds > 0) {
		tvp = ares_timeout(channel, NULL, &tv);
		select(nfds, &read_fds, &write_fds, NULL, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}
}

int wget_async_dns_create(wget_async_dns **async_dns, wget_dns *dns, int maxwaiting, int timeout, int maxtries)
{
	int status;
	wget_async_dns *_async_dns = wget_calloc(1, sizeof(wget_async_dns));

	if (!_async_dns)
		return WGET_E_MEMORY;

	_async_dns->nwaiting = 0;
	_async_dns->maxwaiting = maxwaiting ? maxwaiting : MAXWAITING;
	_async_dns->dns = dns;

	status = ares_library_init(ARES_LIB_INIT_ALL);
	if (status != ARES_SUCCESS) {
		error_printf(_("Failed to init c-ares: %s\n"), ares_strerror(status));
		return WGET_E_UNKNOWN;
	}

	struct ares_options options = {
		.timeout = timeout ? timeout : TIMEOUT,     /* set first query timeout */
		.tries = maxtries ? maxtries : MAXTRIES       /* set max. number of tries */
	};

	status = ares_init_options(&_async_dns->channel, &options, ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES);
	if (status != ARES_SUCCESS) {
		error_printf(_("Failed to init c-ares options: %s\n"), ares_strerror(status));
		return WGET_E_UNKNOWN;
	}

	status = ares_set_servers_csv(_async_dns->channel, SERVERS);
	if (status != ARES_SUCCESS) {
		error_printf(_("Failed to set c-ares servers: %s\n"), ares_strerror(status));
		return WGET_E_UNKNOWN;
	}

	*async_dns = _async_dns;

	return WGET_E_SUCCESS;
}


void wget_async_dns_destroy(wget_async_dns **async_dns)
{
	if (async_dns && *async_dns) {
		if ((*async_dns)->channel)
			ares_destroy((*async_dns)->channel);

		ares_library_cleanup();

		xfree(*async_dns);
	}
}

void wget_async_dns_resolve(wget_async_dns *async_dns)
{
	if (async_dns)
		while (async_dns->nwaiting)
			wait_ares(async_dns->channel);
}

void wget_async_dns_add(wget_async_dns *async_dns, const char *host)
{
	if (async_dns) {
		while (async_dns->nwaiting >= async_dns->maxwaiting)
			wait_ares(async_dns->channel);

		ares_gethostbyname(async_dns->channel, host, AF_INET, callback, async_dns);
		async_dns->nwaiting++;
	}
}
