/*
 * Copyright (c) 2020 Free Software Foundation, Inc.
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
 *
 *
 * Example for DNS-over-HTTPS (RFC 8484)
 *
 * For DNS data see RFC 1035 (incl. A Record) and RFC 3596 (AAAA Record)
 */

//#define DOH_SERVER "https://dns.google/dns-query"
#define DOH_POST
#define DOH_SERVER "https://dns.adguard.com/dns-query"
#define DOH_SERVER_IP "176.103.130.130"
#define DOH_SERVER_NAME "dns.adguard.com"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <wget.h>

// see RFC 1035, 4.1.1 Header section format
static size_t create_dns_query(uint8_t *querybuf, size_t size, const char *host, int family)
{
	uint16_t qtype;

	if (family == WGET_NET_FAMILY_IPV4) {
		qtype = ns_t_a;
	} else if (family == WGET_NET_FAMILY_IPV6) {
		qtype = ns_t_aaaa;
	} else {
		qtype = ns_t_any;
	}

	// The following code is the same as
	//   return = res_mkquery(QUERY, host, ns_c_in, type, NULL, 0, NULL, querybuf, size);
	// We try to avoid dependency of -lresolv.

	if (size < 12 + strlen(host) + 1 + 5) {
		fprintf(stderr, "Query buffer too small (%zu)\n", size);
		return -1;
	}

	// HEADER
	memset(querybuf, 0, 12);
	querybuf[2] = 1; // RD=1 (Recursion desired)
	querybuf[5] = 1; // QDCOUNT=1 (number of entries in the question section)

	// QNAME
	uint8_t *d = querybuf + 12 + 1, *n = querybuf + 12;
	for (const char *s = host; *s; s++, d++) {
		if (*s == '.') {
			*n = d - n - 1;
			n = d;
		} else {
			*d = (uint8_t) *s;
		}
	}
	*n = d - n - 1;
	*d++ = 0;

	// QTYPE
	*d++ = qtype >> 8;
	*d++ = qtype & 0xFF;

	// QCLASS (ns_c_in == 1)
	*d++ = 0;
	*d++ = 1;

	return d - querybuf;
}

/*
static size_t create_dns_query(uint8_t *querybuf, size_t size, const char *host, int family)
{
	int type;
	size_t length;

	if (family == WGET_NET_FAMILY_IPV4) {
		type = ns_t_a;
	} else if (family == WGET_NET_FAMILY_IPV6) {
		type = ns_t_aaaa;
	} else {
		type = ns_t_any;
	}

	length = res_mkquery(QUERY, host, ns_c_in, type, NULL, 0, NULL, querybuf, size);

	if ((int) length < 0) {
		fprintf(stderr, "Failed to make DNS query (%d)\n", errno);
		return -1;
	}

	return length;
}
*/

/*
static int get_string(const uint8_t *data, char *out, size_t outsize)
{
	uint8_t olen = *data++;
	uint8_t len = olen;

	if (len >= outsize)
		len = outsize - 1;

	memcpy(out, data, len);
	out[len] = 0;

	return ((int) olen) + 1;
}
*/

int main(int argc WGET_GCC_UNUSED, const char *const *argv WGET_GCC_UNUSED)
{
	wget_iri *uri;
	wget_http_connection *conn = NULL;
	wget_http_request *req = NULL;
	wget_http_response *resp = NULL;

	// We want the libwget debug messages be printed to STDERR.
	// From here on, we can call wget_debug_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_DEBUG), stderr);

	// We want the libwget error messages be printed to STDERR.
	// From here on, we can call wget_error_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_ERROR), stderr);

	// We want the libwget info messages be printed to STDOUT.
	// From here on, we can call wget_info_printf, etc.
	wget_logger_set_stream(wget_get_logger(WGET_LOGGER_INFO), stdout);

	wget_net_init(); // needed for Windows Sockets

	// set DNS cache
	wget_dns_cache *dns_cache;
	if (wget_dns_cache_init(&dns_cache) == 0) {
		wget_dns_set_cache(NULL, dns_cache);
	}

	// load IP/domain into DNS cache to avoid DNS lookup
	wget_dns_cache_ip(NULL, DOH_SERVER_IP, DOH_SERVER_NAME, 443);

	uint8_t dns_data[512];
	size_t dns_data_len = create_dns_query(dns_data, sizeof(dns_data), "www.example.com", WGET_NET_FAMILY_IPV4);

#ifdef DOH_POST
	if (!(uri = wget_iri_parse(DOH_SERVER, NULL))) {
		fprintf(stderr, "Failed to parse %s\n", DOH_SERVER);
		return 1;
	}
#else
	char *dns_data_b64 = wget_base64_encode_alloc(dns_data, dns_data_len);
	char *server_url = wget_aprintf("%s?dns=%s", DOH_SERVER, dns_data_b64);
	free(dns_data_b64); dns_data_b64 = NULL;

	if (!(uri = wget_iri_parse(server_url, NULL))) {
		fprintf(stderr, "Failed to parse %s\n", DOH_SERVER);
		return 1;
	}

	free(server_url); server_url = NULL;
#endif

	wget_ssl_set_config_int(WGET_SSL_OCSP, 0);

	if (wget_http_open(&conn, uri)) {
		fprintf(stderr, "Failed to connect to %s (errno=%d)\n", DOH_SERVER, errno);
		return 1;
	}

#ifdef DOH_POST
	if (!(req = wget_http_create_request(uri, "POST"))) {
		fprintf(stderr, "Failed to create reuqest\n");
		return 1;
	}

	wget_http_request_set_body(req, "application/dns-message", wget_memdup(dns_data, dns_data_len), dns_data_len);
#else
	if (!(req = wget_http_create_request(uri, "GET"))) {
		fprintf(stderr, "Failed to create reuqest\n");
		return 1;
	}
#endif
	wget_http_add_header(req, "Accept", "*/*");

	printf("query length: %zu\n", dns_data_len);
	for (unsigned i = 0	; i < dns_data_len; i++)
		printf("%02X", dns_data[i]);
	printf("\n");

	if (conn) {
		if (wget_http_send_request(conn, req) == 0) {
			resp = wget_http_get_response(conn);

			if (!resp)
				goto out;

			if (resp->body) {
				// let's assume the body is printable
				printf("#########\n");
				printf("body length %zu\n", resp->body->length);

				for (unsigned i = 0	; i < resp->body->length; i++)
					printf("%02X", (uint8_t) resp->body->data[i]);
				printf("\n");

				int n;
				ns_msg msg;

				if (ns_initparse((uint8_t *) resp->body->data, resp->body->length, &msg) != 0) {
					fprintf(stderr, "ns_initparse: Failed to parse msg\n");
					printf("msg=%.*s\n", (int) resp->body->length, resp->body->data);
					goto out;
				}

				n = ns_msg_count(msg, ns_s_an);
				printf("n=%d\n", n);

				ns_rr rr;
				for (int it = 0; it < n; it++) {
					if (ns_parserr(&msg, ns_s_an, it, &rr)) {
						fprintf(stderr, "ns_parserr: Failed at %d\n", it);
						continue;
					}

					const uint8_t *data = ns_rr_rdata(rr);

					printf("[%d] type %u class %u name %s rdlen %zu\n",
						it, ns_rr_type(rr), ns_rr_class(rr), ns_rr_name(rr), ns_rr_rdlen(rr));

					if (ns_rr_type(rr) == ns_t_a) {
						char adr[16];
						printf("  %s\n", inet_ntop(AF_INET, data, adr, sizeof(adr)));
					} else if (ns_rr_type(rr) == ns_t_aaaa) {
						char adr[48];
						printf("  %s\n", inet_ntop(AF_INET6, data, adr, sizeof(adr)));
					}
				}
			}

			wget_http_free_response(&resp);
		}
	}

out:
	wget_http_close(&conn);

	// the following is to satisfy valgrind
	wget_http_free_request(&req);
	wget_iri_free(&uri);
	wget_ssl_deinit();
	wget_net_deinit(); // needed for Windows Sockets

	return 0;
}
