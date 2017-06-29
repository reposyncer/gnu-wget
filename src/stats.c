/*
 * Copyright(c) 2017 Free Software Foundation, Inc.
 *
 * This file is part of Wget.
 *
 * Wget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Statistics
 *
 */
#include <config.h>
#include <wget.h>
#include "wget_main.h"
#include "wget_stats.h"
#include "wget_options.h"

static wget_vector_t *dns_stats_v;
static wget_thread_mutex_t mutex = WGET_THREAD_MUTEX_INITIALIZER;

static void stats_callback(wget_stats_type_t type, const void *stats)
{
	switch(type) {
	case WGET_STATS_TYPE_DNS: {
		dns_stats_t dns_stats;

		dns_stats.host = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_HOST, stats));
		dns_stats.ip = wget_strdup(wget_tcp_get_stats_dns(WGET_STATS_DNS_IP, stats));
		dns_stats.millisecs = *((long long *)wget_tcp_get_stats_dns(WGET_STATS_DNS_SECS, stats));

		wget_thread_mutex_lock(&mutex);
		wget_vector_add(dns_stats_v, &dns_stats, sizeof(dns_stats_t));
		wget_thread_mutex_unlock(&mutex);

		break;
	}

	case WGET_STATS_TYPE_TLS: {
		const char
			*version,
			*false_start,
			*tfo,
			*alpn_proto,
			*tls_con,
			*resumed,
			*tcp_proto;
		unsigned int *cert_chain_size;
		const long long *millisecs;
/*
		version = wget_tcp_get_stats_tls(WGET_STATS_TLS_VERSION, stats);
		false_start = wget_tcp_get_stats_tls(WGET_STATS_TLS_FALSE_START, stats);
		tfo = wget_tcp_get_stats_tls(WGET_STATS_TLS_TFO, stats);
		alpn_proto = wget_tcp_get_stats_tls(WGET_STATS_TLS_ALPN_PROTO, stats);
		milisecs = wget_tcp_get_stats_tls(WGET_STATS_TLS_SECS, stats);
		tls_con = wget_tcp_get_stats_tls(WGET_STATS_TLS_CON, stats);
		resumed = wget_tcp_get_stats_tls(WGET_STATS_TLS_RESUMED, stats);
		tcp_proto = wget_tcp_get_stats_tls(WGET_STATS_TLS_TCP_PROTO, stats);
		cert_chain_size = wget_tcp_get_stats_tls(WGET_STATS_TLS_CERT_CHAIN_SIZE, stats);
*/
		info_printf("%s negotiation took %lld milisecs\n", version, *millisecs);

		break;
	}

	default:
		error_printf("Unknown stats type\n");
		break;
	}
}

static void free_dns_stats(dns_stats_t *stats)
{
	if (stats) {
		xfree(stats->host);
		xfree(stats->ip);
	}
}

void stats_init(void)
{

	if (config.stats_dns) {
		dns_stats_v = wget_vector_create(8, -2, NULL);
		wget_vector_set_destructor(dns_stats_v, (wget_vector_destructor_t) free_dns_stats);
		wget_tcp_set_stats_dns(stats_callback);
	}
//	if (config.stats_tls)
//		wget_tcp_set_stats_tls(stats_callback);
}

void stats_print(void)
{
	if (config.stats_dns) {
		info_printf("\nDNS timings:\n");
		info_printf("  %4s %s\n", "ms", "Host");
		for (int it = 0; it < wget_vector_size(dns_stats_v); it++) {
			const dns_stats_t *dns_stats = wget_vector_get(dns_stats_v, it);
			info_printf("  %4lld %s (%s)\n", dns_stats->millisecs, dns_stats->host, dns_stats->ip);
		}
	}

	wget_vector_free(&dns_stats_v);
}
