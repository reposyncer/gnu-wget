/*
 * Copyright(c) 2015-2018 Free Software Foundation, Inc.
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
 * DNS query routines, with DNS resolvers of various kinds
 */
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include <netdb.h>

#include <resolv.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <wget.h>
#include "private.h"

/**
 * \file
 * \brief Functions to send DNS queries, supporting DNS resolvers of various kinds
 * \defgroup libwget-dns DNS resolvers
 *
 * @{
 *
 * Support for getaddrinfo() and DNS-over-HTTPS types of DNS resolution functions.
 *
 * The following features are supported:
 *
 *	- getaddrinfo() resolver.
 *	- DNS-over-HTTPS resolver (https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-09)
 *
 * Most of the functions here take `wget_dns_t` structure as argument.
 *
 * The `wget_dns_t` structure represents a DNS resolver. You can create it with
 * wget_dns_init() and destroy it with wget_dns_deinit().
 *
 * When we create a new `wget_dns_t` with wget_dns_init(), it is initialized
 * with th following parameters:
 *
 *  - timeout: -1
 *  - DNS caching: Yes
 *  - Family: `AF_UNSPEC` (Basically means "I don't care, pick the first one available).
 *
 */

struct wget_dns_st {
	int
		resolver,
		class,
		type,
		family,
		preferred_family,
		value,
		port,
		timeout;
	char
		*ip;
	const char
		*doh_url; //set a full URL to the DOH server. It is not just a hostname.
	uint32_t
		ttl;
	u_char
		querybuf[PACKETSZ],
		responsebuf[NS_MAXDNAME];
	u_int16_t
		resp_count;
	struct addrinfo
		*addrinfo;
	bool
		caching : 1;
};

static wget_thread_mutex_t
    resolver_mutex;
static bool
	initialized;

static struct wget_dns_st _global_dns = {
   .timeout = -1,
   .family = AF_UNSPEC,
   .caching = 1,
};

static void _wget_dns_init(void)
{
	if(!initialized) {
		wget_thread_mutex_init(&resolver_mutex);
		initialized = 1;
	}
}

/**
 * \return A new `wget_dns_t` structure, with pre-defined parameters.
 *
 * \param[in] tcp An initialized `wget_tcp_t` structure (optional, can be NULL).
 *
 * Create a new DNS context.
 *
 * If \p tcp is given, the DNS context will be configured with the values taken
 * from that TCP connection. The DNS context's family and timeout will be those specified
 * in the given TCP connection. These values correspond to the `WGET_DNS_ADDR_FAMILY` and
 * `WGET_DNS_TIMEOUT`.
 *
 * If no \p tcp is given, then the new DNS context will be initialized with default configuration values.
 * These can be changed at any time with wget_dns_set_config_int().
 *
 * The new DNS context will use the standard getaddrinfo(3) resolver by default. This can later be changed
 * with wget_dns_set_config_int() and wget_dns_set_config_string().
 */
wget_dns_t *wget_dns_init(void)
{
	_wget_dns_init();

	wget_dns_t *dns = xmalloc(sizeof(wget_dns_t));

	*dns = _global_dns;
	return dns;
}

static void _wget_dns_exit(void)
{
	if (initialized) {
		wget_thread_mutex_destroy(&resolver_mutex);
		initialized = 0;
	}
}

/**
 * \param[in] dns A pointer to a `wget_dns_t` structure.
 *
 * Delete a DNS context.
 *
 * Delete the DNS context previously created with wget_dns_init(), and set the given
 * pointer to NULL.
 */
void wget_dns_deinit(wget_dns_t **dns)
{
	_wget_dns_exit();

	if (dns && *dns) {
		xfree(*dns);
	}
}

/**
 * \param[in] dns A DNS context
 * \param[in] key An identifier for the config parameter (starting with `WGET_DNS_`)
 * \param[in] value The value for the config parameter
 *
 * Set a configuration parameter, as an integer.
 *
 * A list of available parameters follows (possible values for \p key).
 *
 *  - WGET_DNS_TIMEOUT: sets the request timeout, in milliseconds. This is the maximum time
 *  wget_dns_resolve() will wait for a DNS query to complete. This might have the value zero (0),
 *  which will cause wget_dns_resolve() to return immediately, or a negative value which will cause it
 *  to wait indefinitely (until the response arrives or the thread is interrupted).
 *  - WGET_DNS_ADDR_FAMILY: sets the preferred address family. This is the address family wget_dns_resolve()
 *  will favor above the others, when more than one address families are returned for the query. This will
 *  typically be `AF_INET` or `AF_INET6`, but it can be any of the values defined in `<socket.h>`. Additionally,
 *  `AF_UNSPEC` means you don't care.
 *  - WGET_DNS_PORT: sets the port for the DOH server for the query or this
 *  must get the port in the URL to the DOH server and specify it in here.
 *  - WGET_DNS_RESOLVER: sets the resolver that will be used. The list that follows describes the available
 *  resolvers.
 *
 * Currently the following DNS resolvers are supported:
 *
 *  - WGET_DNS_RESOLVER_DOH: DNS-over-HTTPS resolver, speaking the protocol defined in draft-ietf-doh-dns-over-https-07*.
 *  This requires a URL that must be set with the WGET_DNS_RESOLVER_DOH_URL option
 *  by calling wget_dns_set_config_string().
 *  - WGET_DNS_RESOLVER_GETADDRINFO: A standard resolver using the getaddrinfo(3) system call.
 *
 * * https://tools.ietf.org/html/draft-ietf-doh-dns-over-https-07
 */
void wget_dns_set_config_int(wget_dns_t *dns, int key, int value)
{
	switch (key) {
	case WGET_DNS_ADDR_FAMILY:
		dns->family = value;
		break;
	case WGET_DNS_ADDR_CLASS:
		dns->class = value;
		break;
	case WGET_DNS_TIMEOUT:
		dns->timeout = value;
		break;
	case WGET_DNS_PORT:
		dns->port = value;
		break;
	case WGET_DNS_RESOLVER:
		if (value == WGET_DNS_RESOLVER_DOH || value == WGET_DNS_RESOLVER_GETADDRINFO)
			dns->resolver = value;
		else
			error_printf(_("Invalid value for config key WGET_DNS_RESOLVER (%d)\n"), value);
		break;
	default:
		error_printf(_("Unknown config key %d\n"), key);
		break;
	}
}

/**
 * \param[in] dns A DNS context
 * \param[in] key An identifier for the config parameter
 * \oaram[in] value The value for the config parameter
 *
 * The only available parameter currently is WGET_DNS_RESOLVER_DOH_URL, which sets
 * the target URL of the server to send and request for a DoH query.
 */
void wget_dns_set_config_string(wget_dns_t *dns, int key, const char *value)
{
	if (key == WGET_DNS_RESOLVER_DOH_URL)
		dns->doh_url = value;
	else
		error_printf(_("Unknown config key %d\n"), key);
}

/**
 * \param[in] dns A DNS context
 * \param[in] host Hostname
 * \param[in] port TCP destination port
 * \param[in] out_addr A pointer to an `addrinfo` structure that will hold the result
 * \return The number of items in `addrinfo` on success; a negative number on error
 *
 * Resolve a host name into its IPv4/IPv6 address.
 *
 * A new `addrinfo` structure will be allocated and the result will be placed there.
 * **The caller is responsible for freeing it.**
 *
 * This function will honor the configuration parameters set in the DNS context
 * previously with wget_dns_set_config_int() and wget_dns_set_config_string().
 *
 * The `addrinfo` structure is a linked list that may contain more than one addresses
 * for the queried host name. The addresses in the list will be sorted according the preferred
 * family that was specified, if any.
 *
 * If the preferred family configuration parameter was set, all addresses with that family
 * will come first in the list, and other families will follow. For example, if `AF_INET` was set
 * as the preferred family, all IPv4 addresses returned by the query will come first in the list,
 * and any IPv6 addresses will come after them, if any were returned.
 */
// we can't provide a portable way of respecting a DNS timeout
int wget_dns_getaddrinfo_resolve(int family, int flags, const char *host, uint16_t port, struct addrinfo **out_addr)
{
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_ADDRCONFIG | flags
	};

	if (port) {
		char s_port[NI_MAXSERV];

		hints.ai_flags |= AI_NUMERICSERV;

		wget_snprintf(s_port, sizeof(s_port), "%hu", port);
		debug_printf("resolving %s:%s...\n", host ? host : "", s_port);
		return getaddrinfo(host, s_port, &hints, out_addr);
	} else {
		debug_printf("resolving %s...\n", host);
		return getaddrinfo(host, NULL, &hints, out_addr);
	}
}

/**
 * Makes a DNS query and provdes you with the host address(A type) or even the
 * IPv6 address according to the type you provide to retrieve.
 * \param[in] host Hostname
 * \param[in] class Value for class field in the DNS. It has been set to ns_c_any
 * as in a wildcard match from the nameser.h header. It can be ns_c_in for
 * internet class too according to the wish.
 * \param[in] type This defines what record you wish to attain ns_t_a or
 * ns_t_aaaa on which the user wish to resolve the query with and obtain the
 * address.
 *
 * \return The size of the response, or it fills in h_errno and returns -1 if
 * there was an error or the answer count was zero
 *
 * Makes the DNS query we use res_mkquery() which stores the result of the
 * query in the querybuf and returns the length of the buffer.
 *
 * This function queries to the following records:
 *  - A (IPv4)
 *  - AAAA (IPv6)
 *
 */
int wget_dns_query(const char* host, int class, int type)
{

	ns_msg message;
	ns_rr rr;

	wget_dns_t *dns = wget_dns_init();

	wget_thread_mutex_lock(resolver_mutex);

	int length = res_mkquery(QUERY, host, class, type, NULL, 0, NULL,  dns->querybuf, sizeof(dns->querybuf));

	if (length < 0)
		perror(host);

	if (ns_rr_type(rr) == type) {
		dns->ttl = ns_rr_ttl(rr);
	}

	wget_thread_mutex_unlock(resolver_mutex);

	return length;
}

/**
 *
 * \param[in] dns A DNS context
 * \param[in] host The Hostname
 * \param[in] doh_server URL to the resolver DOH server
 * \param[in] type The DNS type
 * \param[in] class The DNS class that the DNS type exists
 *
 * wget_doh_encode() creates the type(IPv4 or IPv6) DOH request according to the
 * parameters given to it. That is, This function encodes a single DNS A or
 * AAAA query into a HTTP request. We make use of GET HTTP request to wrap
 * around the DNS query and according to the DOH standards the DNS query is
 * being base64 encoded.
 *
 */

wget_http_response_t *wget_doh_encode(wget_dns_t *dns, const char *host, const char *doh_server, int family, int class)
{
	wget_http_request_t *req;
	wget_http_connection_t *conn = NULL;
	wget_iri_t *uri;
	dns = wget_dns_init();

	wget_net_init(); // needed for Windows Sockets

	wget_global_init(
			WGET_DEBUG_STREAM, stderr,
			WGET_ERROR_STREAM, stderr,
			WGET_INFO_STREAM, stdout,
			WGET_DNS_CACHING, 1,
			0);

	char payload_b64[wget_base64_get_encoded_length(sizeof(dns->querybuf))];
	int rc;

	wget_dns_set_config_int(dns, WGET_DNS_RESOLVER, WGET_DNS_RESOLVER_DOH);
	wget_dns_set_config_string(dns, WGET_DNS_RESOLVER_DOH_URL, wget_strdup(doh_server));

	wget_dns_set_config_int(dns, WGET_DNS_ADDR_FAMILY, family);

	if (dns->family == WGET_DNS_ADDR_A_FAMILY) {
		rc = wget_dns_query(host, ns_c_in, ns_t_a);
	} else if (dns->family == WGET_DNS_ADDR_AAAA_FAMILY) {
		rc = wget_dns_query(host, ns_c_in, ns_t_aaaa);
	} else {
		debug_printf("Failed to create the dns packet, length: %d\n", rc);
	}

	wget_base64_urlencode(payload_b64, dns->querybuf, sizeof(dns->querybuf));

	char *url = wget_aprintf("%s?dns=%s", doh_server, payload_b64);
	uri = wget_iri_parse(url, NULL);

	if (!uri) {
		error_printf (_("Error parsing the URL\n"));
		goto out;
	}

	req = wget_http_create_request(uri, "GET");
	wget_http_add_header(req, "Accept", "Application/dns-message");

	wget_http_request_set_int(req, WGET_HTTP_RESPONSE_KEEPHEADER, 1);

	//Keep the connection alive
	wget_http_add_header(req, "Connection", "keep-alive");

	// 4. establish connection to the host/port given by uri
	wget_http_open(&conn, uri);

	if (conn) {
		wget_http_response_t *resp;

		if (wget_http_send_request(conn, req) == 0) {
			resp = wget_http_get_response(conn);

			if (!resp)
				goto out;

			// server doesn't want to support keep-alive
			if (!resp->keep_alive)
				wget_http_close(&conn);

			// let's assume the body isn't binary (doesn't contain \0)
			wget_info_printf("%s%s\n", resp->header->data, resp->body->data);

			return resp;

			wget_http_free_response(&resp);
		}
	}

out:
	wget_http_close(&conn);
	wget_http_free_request(&req);
	wget_iri_free(&uri);

	wget_dns_deinit(&dns);
	wget_net_deinit();
	return NULL;
}

/**
 * \param[in] dns A DNS context
 * \param[in] host The Hostname
 * \param[in] doh_server The URL to the resolver DOH server
 * \param[in] family Denotes the DNS type. Either A or AAAA
 * \param[in] out_addr A pointer towards addrinfo struct storing the
 * results after the resolution through DOH.
 *
 * wget_doh_resolve() resolves a name using DOH. It resolves the  name stores
 * them into an addrinfo structure.
 *
 * Returns:
 *		0, if success
 *		-1, if failed
 *
 */

int wget_doh_resolve(wget_dns_t *dns, const char *host, const char *doh_server, uint16_t port, int family)
{
	struct addrinfo *addrinfo = NULL;

	wget_http_response_t *resp;

	if (!dns)
		// No input means no output
		return -1;

	wget_dns_set_config_int(dns, WGET_DNS_ADDR_FAMILY, family);
	wget_dns_set_config_int(dns, WGET_DNS_ADDR_CLASS, C_IN);

	int dnsquery = wget_dns_query(host, dns->class, dns->family);

	resp = wget_doh_encode(dns, host, doh_server, dns->family, dns->class);

	int dohdecode = wget_doh_decode(dns, resp, dns->family);

	// FIXME: if dohdecode returns error (-1)

	wget_tcp_dns_cache_add(dns->ip, host, port);

	return 0;
}

/**
 * A DoH server will respond with a body that is identical to a response from your
 * typical DNS server RFC 1035 describes the layout of that response.There's
 * really no difference - that's one of the main points with DoH.
 *
 * Return value:
 *		-1 error
 *		 0 success
 *
 * On success, it stores the converted IP address in dns->ip as a char field.
 */

int wget_doh_decode(wget_dns_t *dns, wget_http_response_t *resp, int family)
{
	ns_msg message;
	ns_rr rr;
	char ip[64];
	int net_family;

	if (family == WGET_NET_FAMILY_IPV4)
		net_family = AF_INET;
	else if (family == WGET_NET_FAMILY_IPV6)
		net_family = AF_INET6;
	else
		return -1;

	ns_initparse(resp->body->data, resp->body->length, &message);

	int count = ns_msg_count(message, ns_s_an);

	if (wget_strcasecmp_ascii(resp->content_type, "application/dns-message") || resp->code == 415) {
		error_printf("Unsupported media type: %s", resp->content_type);
		return -1;
	}

	if (count == 0)
		return -1;

	for (int i = 0; i < count; i++) {
		if (ns_parserr(&message, ns_s_an, i, &rr) < 0) {
			fprintf(stderr, "ns_parserr failed at: %d\n", i);
			return -1;
		}

		// const uint8_t *data = ns_rr_rdata(rr);

		if (inet_ntop(net_family, ns_rr_rdata(rr), ip, sizeof(ip))) {
			wget_dns_set_config_int(dns, WGET_DNS_ADDR_FAMILY, family);
			xfree(dns->ip);
			dns->ip = wget_strdup(ip);
			return 0;
		}
	}

	return -1;
}
