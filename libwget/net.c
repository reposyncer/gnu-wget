/*
 * Copyright (c) 2012 Tim Ruehsen
 * Copyright (c) 2015-2024 Free Software Foundation, Inc.
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
 * network routines
 *
 * Changelog
 * 25.04.2012  Tim Ruehsen  created
 * 16.11.2012               new functions tcp_set_family() and tcp_set_preferred_family()
 *
 * RFC 7413: TCP Fast Open
 */

#include <config.h>

#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <c-ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>

#ifdef HAVE_NETINET_TCP_H
#	include <netinet/tcp.h>
#endif

#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <sys/ioctl.h>
#else
# include <fcntl.h>
#endif

#if defined __APPLE__ && defined __MACH__ && defined CONNECT_DATA_IDEMPOTENT && defined CONNECT_RESUME_ON_READ_WRITE
# define TCP_FASTOPEN_OSX
#elif defined TCP_FASTOPEN_CONNECT // since Linux 4.11
# define TCP_FASTOPEN_LINUX_411
#elif defined TCP_FASTOPEN && defined MSG_FASTOPEN
# define TCP_FASTOPEN_LINUX
#endif

#include <wget.h>
#include "private.h"
#include "net.h"

/**
 * \file
 * \brief Functions to work with TCP sockets and SSL/TLS
 * \defgroup libwget-net TCP sockets
 *
 * @{
 *
 * TCP sockets and DNS cache management functions.
 *
 * The following features are supported:
 *
 *  - TCP Fast Open ([RFC 7413](https://tools.ietf.org/html/rfc7413))
 *  - SSL/TLS
 *
 * Most functions here take a `wget_tcp` structure as argument.
 *
 * The `wget_tcp` structure represents a TCP connection. You create it with wget_tcp_init()
 * and destroy it with wget_tcp_deinit(). You can connect to a remote host with wget_tcp_connect(),
 * or listen for incoming connections (and accept them) with wget_tcp_listen() and wget_tcp_accept().
 * You end a connection with wget_tcp_close().
 *
 * There are several knobs you can use to customize the behavior of most functions here.
 * The list that follows describes the most important parameters, although you can look at the getter and setter
 * functions here to see them all (`wget_tcp_get_xxx`, `wget_tcp_set_xxx`).
 *
 *  - Timeout: maximum time to wait for an operation to complete. For example, for wget_tcp_read(), it sets the maximum time
 *  to wait until some data is available to read. Most functions here can be non-blocking (with timeout = 0) returning immediately
 *  or they can block indefinitely until something happens (with timeout = -1). For any value greater than zero,
 *  the timeout is taken as milliseconds.
 *  - Family and preferred family: these are used to determine which address family should be used when resolving a host name or
 *  IP address. You probably use `AF_INET` or `AF_INET6` most of the time. The first one forces the library to use that family,
 *  failing if it cannot find any IP address with it. The second one is just a hint, about which family you would prefer; it will try
 *  to get an address of that family if possible, and will get another one if not.
 *  - SSL/TLS: do you want to use TLS?
 *
 *  When you create a new `wget_tcp` with wget_tcp_init(), it is initialized with the following parameters:
 *
 *   - Timeout: -1
 *   - Connection timeout (max. time to wait for a connection to be accepted by the remote host): -1
 *   - DNS timeout (max. time to wait for a DNS query to return): -1
 *   - Family: `AF_UNSPEC` (basically means "I don't care, pick the first one available").
 */

static struct wget_tcp_st global_tcp = {
	.sockfd = -1,
	.dns_timeout = -1,
	.connect_timeout = -1,
	.timeout = -1,
	.family = AF_UNSPEC,
#if defined TCP_FASTOPEN_OSX
	.tcp_fastopen = 1,
#elif defined TCP_FASTOPEN_LINUX_411
	.tcp_fastopen = 1,
#elif defined TCP_FASTOPEN_LINUX
	.tcp_fastopen = 1,
	.first_send = 1,
#endif
};

/* for Windows compatibility */
#include "sockets.h"

#ifdef TCP_FASTOPEN_LINUX
// helper function to give context for errors
static inline void print_error(const wget_tcp *tcp, const char *msg)
{
	error_printf(_("%s (hostname='%s', ip=%s, errno=%d)\n"),
		msg, tcp->host ? tcp->host: "", tcp->ip ? tcp->ip : "", errno);
}
#endif

static inline void print_error_host(const char *msg, const char *host)
{
	error_printf(_("%s (hostname='%s', errno=%d)\n"),
		msg, host, errno);
}

/**
 * \return 0 for success, else failure
 *
 * Initialize the resources needed for network operations.
 */
int wget_net_init(void)
{
	int rc = gl_sockets_startup(SOCKETS_2_2);

	return rc ? -1 : 0;
}

/**
 * \return 0 for success, else failure
 *
 * Free the resources allocated by wget_net_init().
 */
int wget_net_deinit(void)
{
	int rc = gl_sockets_cleanup();

	return rc ? -1 : 0;
}

static int WGET_GCC_CONST value_to_family(int value)
{
	switch (value) {
	case WGET_NET_FAMILY_IPV4:
		return AF_INET;
	case WGET_NET_FAMILY_IPV6:
		return AF_INET6;
	default:
		return AF_UNSPEC;
	}
}

static int WGET_GCC_CONST family_to_value(int family)
{
	switch (family) {
	case AF_INET:
		return WGET_NET_FAMILY_IPV4;
	case AF_INET6:
		return WGET_NET_FAMILY_IPV6;
	default:
		return WGET_NET_FAMILY_ANY;
	}
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \param[in] protocol The protocol, either WGET_PROTOCOL_HTTP_2_0 or WGET_PROTOCOL_HTTP_1_1.
 *
 * Set the protocol for the connection provided, or globally.
 *
 * If \p tcp is NULL, theprotocol will be set globally (for all connections). Otherwise,
 * only for the provided connection (\p tcp).
 */
void wget_tcp_set_dns(wget_tcp *tcp, wget_dns *dns)
{
	(tcp ? tcp : &global_tcp)->dns = dns;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \param[in] tcp_fastopen 1 or 0, whether to enable or disable TCP Fast Open.
 *
 * Enable or disable TCP Fast Open ([RFC 7413](https://tools.ietf.org/html/rfc7413)), if available.
 *
 * This function is a no-op on systems where TCP Fast Open is not supported.
 *
 * If \p tcp is NULL, TCP Fast Open is enabled or disabled globally.
 */
void wget_tcp_set_tcp_fastopen(wget_tcp *tcp, bool tcp_fastopen)
{
#if defined TCP_FASTOPEN_OSX || defined TCP_FASTOPEN_LINUX || defined TCP_FASTOPEN_LINUX_411
	(tcp ? tcp : &global_tcp)->tcp_fastopen = tcp_fastopen;
#else
	(void) tcp; (void) tcp_fastopen;
#endif
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \return 1 if TCP Fast Open is enabled, 0 otherwise.
 *
 * Tells whether TCP Fast Open is enabled or not.
 *
 * You can enable and disable it with wget_tcp_set_tcp_fastopen().
 */
bool wget_tcp_get_tcp_fastopen(wget_tcp *tcp)
{
	return (tcp ? tcp : &global_tcp)->tcp_fastopen;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \param[in] false_start 1 or 0, whether to enable or disable TLS False Start.
 *
 * Enable or disable TLS False Start ([RFC 7918](https://tools.ietf.org/html/rfc7413)).
 *
 * If \p tcp is NULL, TLS False Start is enabled or disabled globally.
 */
void wget_tcp_set_tls_false_start(wget_tcp *tcp, bool false_start)
{
	(tcp ? tcp : &global_tcp)->tls_false_start = false_start;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \return 1 if TLS False Start is enabled, 0 otherwise.
 *
 * Tells whether TLS False Start is enabled or not.
 *
 * You can enable and disable it with wget_tcp_set_tls_false_start().
 */
bool wget_tcp_get_tls_false_start(wget_tcp *tcp)
{
	return (tcp ? tcp : &global_tcp)->tls_false_start;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \param[in] protocol The protocol, either WGET_PROTOCOL_HTTP_2_0 or WGET_PROTOCOL_HTTP_1_1.
 *
 * Set the protocol for the connection provided, or globally.
 *
 * If \p tcp is NULL, theprotocol will be set globally (for all connections). Otherwise,
 * only for the provided connection (\p tcp).
 */
void wget_tcp_set_protocol(wget_tcp *tcp, int protocol)
{
	(tcp ? tcp : &global_tcp)->protocol = protocol;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \return The protocol with this connection, currently WGET_PROTOCOL_HTTP_2_0 or WGET_PROTOCOL_HTTP_1_1.
 *
 * Get protocol used with the provided connection, or globally (if \p tcp is NULL).
 */
int wget_tcp_get_protocol(wget_tcp *tcp)
{
	return (tcp ? tcp : &global_tcp)->protocol;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \param[in] family One of the socket families defined in `<socket.h>`, such as `AF_INET` or `AF_INET6`.
 *
 * Tells the preferred address family that should be used when establishing a TCP connection.
 *
 * wget_tcp_resolve() will favor that and pick an address of that family if possible.
 *
 * If \p tcp is NULL, the preferred address family will be set globally.
 */
void wget_tcp_set_preferred_family(wget_tcp *tcp, int family)
{
	(tcp ? tcp : &global_tcp)->preferred_family = value_to_family(family);
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \return One of the socket families defined in `<socket.h>`, such as `AF_INET` or `AF_INET6`.
 *
 * Get the preferred address family that was previously set with wget_tcp_set_preferred_family().
 */
int wget_tcp_get_preferred_family(wget_tcp *tcp)
{
	return family_to_value((tcp ? tcp : &global_tcp)->preferred_family);
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \param[in] family One of the socket families defined in `<socket.h>`, such as `AF_INET` or `AF_INET6`.
 *
 * Tell the address family that will be used when establishing a TCP connection.
 *
 * wget_tcp_resolve() will pick an address of that family, or fail if it cannot find one.
 *
 * If \p tcp is NULL, the address family will be set globally.
 */
void wget_tcp_set_family(wget_tcp *tcp, int family)
{
	(tcp ? tcp : &global_tcp)->family = value_to_family(family);
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \return One of the socket families defined in `<socket.h>`, such as `AF_INET` or `AF_INET6`.
 *
 * Get the address family that was previously set with wget_tcp_set_family().
 */
int wget_tcp_get_family(wget_tcp *tcp)
{
	return family_to_value((tcp ? tcp : &global_tcp)->family);
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \return The local port.
 *
 * Get the port number the TCP connection \p tcp is bound to on the local machine.
 */
int wget_tcp_get_local_port(wget_tcp *tcp)
{
	if (unlikely(!tcp))
		return 0;

	struct sockaddr_storage addr_store;
	struct sockaddr *addr = (struct sockaddr *)&addr_store;
	socklen_t addr_len = sizeof(addr_store);

	/* Get automatically retrieved port number */
	if (getsockname(tcp->sockfd, addr, &addr_len) == 0) {
		char s_port[NI_MAXSERV];

		if (getnameinfo(addr, addr_len, NULL, 0, s_port, sizeof(s_port), NI_NUMERICSERV) == 0)
			return atoi(s_port);
	}

	return 0;
}

/**
 * \param[in] tcp A TCP connection.
 * \param[in] timeout The timeout value.
 *
 * Set the timeout for the TCP connection.
 *
 * This is the maximum time to wait until the remote host accepts our connection.
 *
 * The following two values are special:
 *
 *  - `0`: No timeout, immediate.
 *  - `-1`: Infinite timeout. Wait indefinitely.
 */
void wget_tcp_set_connect_timeout(wget_tcp *tcp, int timeout)
{
	(tcp ? tcp : &global_tcp)->connect_timeout = timeout;
}

/**
 * \param[in] tcp A TCP connection.
 * \param[in] timeout The timeout value.
 *
 * Set the timeout (in milliseconds) for wget_tcp_read(), wget_tcp_write() and wget_tcp_accept().
 *
 * The following two values are special:
 *
 *  - `0`: No timeout, immediate.
 *  - `-1`: Infinite timeout. Wait indefinitely.
 */
void wget_tcp_set_timeout(wget_tcp *tcp, int timeout)
{
	(tcp ? tcp : &global_tcp)->timeout = timeout;
}

/**
 * \param[in] tcp A TCP connection.
 * \return The timeout value that was set with wget_tcp_set_timeout().
 *
 * Get the timeout value that was set with wget_tcp_set_timeout().
 */
int wget_tcp_get_timeout(wget_tcp *tcp)
{
	return (tcp ? tcp : &global_tcp)->timeout;
}

/**
 * \param[in] tcp A TCP connection. Might be NULL.
 * \param[in] bind_address An IP address or host name.
 *
 * Set the IP address/hostname the socket \p tcp will bind to on the local machine
 * when connecting to a remote host.
 *
 * The hostname can explicitly set the port after a colon (':').
 *
 * This is mainly relevant to wget_tcp_connect().
 * 
 * Can be generelised for TCP and QUIC. Pending.
 */
void wget_tcp_set_bind_address(wget_tcp *tcp, const char *bind_address)
{
	if (!tcp)
		tcp = &global_tcp;

	wget_dns_freeaddrinfo(tcp->dns, &tcp->bind_addrinfo);

	if (bind_address) {
		const char *host, *s = bind_address;

		if (*s == '[') {
			/* IPv6 address within brackets */
			char *p = strrchr(s, ']');
			if (p) {
				host = s + 1;
				s = p + 1;
			} else {
				/* Something is broken */
				host = s + 1;
				while (*s)
					s++;
			}
		} else {
			host = s;
			while (*s && *s != ':')
				s++;
		}

		if (*s == ':') {
			char port[6];

			wget_strscpy(port, s + 1, sizeof(port));

			if (c_isdigit(*port))
				tcp->bind_addrinfo = wget_dns_resolve(tcp->dns, host, (uint16_t) atoi(port), tcp->family, tcp->preferred_family, WGET_TCP_CONNECTION);
		} else {
			tcp->bind_addrinfo = wget_dns_resolve(tcp->dns, host, 0, tcp->family, tcp->preferred_family, WGET_TCP_CONNECTION);
		}
	}
}

/**
 * \param[in] tcp A TCP connection. Might be NULL.
 * \param[in] bind_interface A network interface name.
 *
 * Set the Network Interface the socket \p tcp will bind to on the local machine
 * when connecting to a remote host.
 *
 * This is mainly relevant to wget_tcp_connect().
 */
void wget_tcp_set_bind_interface(wget_tcp *tcp, const char *bind_interface)
{
	if (!tcp)
		tcp = &global_tcp;

	tcp->bind_interface = bind_interface;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \param[in] ssl Flag to enable or disable SSL/TLS on the given connection.
 *
 * Enable or disable SSL/TLS.
 *
 * If \p tcp is NULL, TLS will be enabled globally. Otherwise, TLS will be enabled only for the provided connection.
 */
void wget_tcp_set_ssl(wget_tcp *tcp, bool ssl)
{
	(tcp ? tcp : &global_tcp)->ssl = ssl;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \return 1 if TLs is enabled, 0 otherwise.
 *
 * Tells whether TLS is enabled or not.
 */
bool wget_tcp_get_ssl(wget_tcp *tcp)
{
	return (tcp ? tcp : &global_tcp)->ssl;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \return IP address as string, NULL if not available.
 *
 * Returns the IP address of a `wget_tcp` instance.
 */
const char *wget_tcp_get_ip(wget_tcp *tcp)
{
	return tcp ? tcp->ip : NULL;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \param[in] hostname A hostname. The value of the SNI field.
 *
 * Sets the TLS Server Name Indication (SNI). For more info see [RFC 6066, sect. 3](https://tools.ietf.org/html/rfc6066#section-3).
 *
 * SNI basically does at the TLS layer what the `Host:` header field does at the application (HTTP) layer.
 * The server might use this information to locate an appropriate X.509 certificate from a pool of certificates, or to direct
 * the request to a specific virtual host, for instance.
 */
void wget_tcp_set_ssl_hostname(wget_tcp *tcp, const char *hostname)
{
	if (!tcp)
		tcp = &global_tcp;

	xfree(tcp->ssl_hostname);
	tcp->ssl_hostname = wget_strdup(hostname);
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 * \return A hostname. The value of the SNI field.
 *
 * Returns the value that was set to SNI with a previous call to wget_tcp_set_ssl_hostname().
 */
const char *wget_tcp_get_ssl_hostname(wget_tcp *tcp)
{
	return (tcp ? tcp : &global_tcp)->ssl_hostname;
}

/**
 * \return A new `wget_tcp` structure, with pre-defined parameters.
 *
 * Create a new `wget_tcp` structure, that represents a TCP connection.
 * It can be destroyed with wget_tcp_deinit().
 *
 * This function does not establish or modify a TCP connection in any way.
 * That can be done with the other functions in this file, such as
 * wget_tcp_connect() or wget_tcp_listen() and wget_tcp_accept().
 */
wget_tcp *wget_tcp_init(void)
{
	wget_tcp *tcp = wget_malloc(sizeof(wget_tcp));

	if (tcp) {
		*tcp = global_tcp;
		tcp->ssl_hostname = wget_strdup(global_tcp.ssl_hostname);
	}

	return tcp;
}

/**
 * \param[in] _tcp A **pointer** to a `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init(). Might be NULL.
 *
 * Release a TCP connection (created with wget_tcp_init()).
 *
 * The `wget_tcp` structure will be freed and \p _tcp will be set to NULL.
 *
 * If \p _tcp is NULL, the SNI field will be cleared.
 *
 * Does not free the internal DNS cache, so that other connections can reuse it.
 * Call wget_dns_cache_free() if you want to free it.
 */
void wget_tcp_deinit(wget_tcp **_tcp)
{
	wget_tcp *tcp;

	if (!_tcp) {
		xfree(global_tcp.ssl_hostname);
		return;
	}

	if ((tcp = *_tcp)) {
		wget_tcp_close(tcp);

		wget_dns_freeaddrinfo(tcp->dns, &tcp->bind_addrinfo);

		xfree(tcp->ssl_hostname);
		xfree(tcp->ip);
		xfree(tcp);

		*_tcp = NULL;
	}
}

static void _set_async(int fd)
{
#if ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
	unsigned long blocking = 0;

	if (ioctl(fd, FIONBIO, &blocking))
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#else
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
		error_printf_exit(_("Failed to get socket flags\n"));

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		error_printf_exit(_("Failed to set socket to non-blocking\n"));
#endif
}

static void set_socket_options(const wget_tcp *tcp, int fd)
{
	int on = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) == -1)
		error_printf(_("Failed to set socket option REUSEADDR\n"));

	on = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&on, sizeof(on)) == -1)
		error_printf(_("Failed to set socket option NODELAY\n"));

#ifdef SO_BINDTODEVICE
	if (tcp->bind_interface) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, tcp->bind_interface, (socklen_t)strlen(tcp->bind_interface)) == -1)
			error_printf(_("Failed to set socket option BINDTODEVICE\n"));
	}
#else
	// Let's exit here instead of using a wrong interface (privacy concerns)
	if (tcp->bind_interface)
		error_printf_exit(_("Unsupported socket option BINDTODEVICE\n"));
#endif

#ifdef TCP_FASTOPEN_LINUX_411
	on = 1;
	if (setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, (void *)&on, sizeof(on)) == -1)
		debug_printf("Failed to set socket option TCP_FASTOPEN_CONNECT\n");
#endif
}

/**
 * Test whether the given connection (\p tcp) is ready to read or write.
 *
 * The parameter \p flags can have one or both (with bitwise OR) of the following values:
 *
 *  - `WGET_IO_READABLE`: Is data available for reading?
 *  - `WGET_IO_WRITABLE`: Can we write immediately (without having to wait until the TCP buffer frees)?
 */
int wget_tcp_ready_2_transfer(wget_tcp *tcp, int flags)
{
	if (likely(tcp))
		return wget_ready_2_transfer(tcp->sockfd, tcp->timeout, flags);
	else
		return -1;
}

static void debug_addr(const char *caption, const struct sockaddr *ai_addr, socklen_t ai_addrlen)
{
	int rc;
	char adr[NI_MAXHOST], s_port[NI_MAXSERV];

	rc = getnameinfo(ai_addr, ai_addrlen,
			 adr, sizeof(adr),
			 s_port, sizeof(s_port),
			 NI_NUMERICHOST | NI_NUMERICSERV);
	if (rc == 0) {
		if (ai_addr->sa_family == AF_INET6)
			debug_printf("%s [%s]:%s...\n", caption, adr, s_port);
		else
			debug_printf("%s %s:%s...\n", caption, adr, s_port);
	} else
		debug_printf("%s ???:%s (%s)...\n", caption, s_port, gai_strerror(rc));
}

static int tcp_connect(wget_tcp *tcp, struct addrinfo *ai, int sockfd)
{
	int rc;

	/* Enable TCP Fast Open, if required by the user and available */
#ifdef TCP_FASTOPEN_OSX
	if (tcp->tcp_fastopen) {
		sa_endpoints_t endpoints = { .sae_dstaddr = ai->ai_addr, .sae_dstaddrlen = ai->ai_addrlen };
		rc = connectx(sockfd, &endpoints,
			      SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, NULL, 0, NULL, NULL);
		tcp->first_send = 0;
#elif defined TCP_FASTOPEN_LINUX
	if (tcp->tcp_fastopen) {
		errno = 0;
		tcp->connect_addrinfo = ai;
		rc = 0;
		tcp->first_send = 1;
#elif defined TCP_FASTOPEN_LINUX_411
	if (tcp->tcp_fastopen) {
		tcp->connect_addrinfo = ai;
		rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
		tcp->first_send = 0;
#else
	if (0) {
#endif
	} else {
		rc = connect(sockfd, ai->ai_addr, ai->ai_addrlen);
		tcp->first_send = 0;
	}

	return rc;
}

/**
 * \param[in] tcp A `wget_tcp` structure representing a TCP connection, returned by wget_tcp_init().
 * \param[in] host Hostname or IP address to connect to.
 * \param[in] port port number
 * \return WGET_E_SUCCESS (0) on success, or a negative integer on error (some of WGET_E_XXX defined in `<wget.h>`).
 *
 * Open a TCP connection with a remote host.
 *
 * This function will use TLS if it has been enabled for this `wget_tcp`. You can enable it
 * with wget_tcp_set_ssl(). Additionally, you can also use wget_tcp_set_ssl_hostname() to set the
 * Server Name Indication (SNI).
 *
 * You can set which IP address and port on the local machine will the socket be bound to
 * with wget_tcp_set_bind_address(). Otherwise the socket will bind to any address and port
 * chosen by the operating system.
 *
 * You can also set which Network Interface on the local machine will the socket be bound to
 * with wget_tcp_bind_interface().
 *
 * This function will try to use TCP Fast Open if enabled and available. If TCP Fast Open fails,
 * it will fall back to the normal TCP handshake, without raising an error. You can enable TCP Fast Open
 * with wget_tcp_set_tcp_fastopen().
 *
 * If the connection fails, `WGET_E_CONNECT` is returned.
 */
int wget_tcp_connect(wget_tcp *tcp, const char *host, uint16_t port)
{
	struct addrinfo *ai;
	int rc, ret = WGET_E_UNKNOWN;
	char adr[NI_MAXHOST], s_port[NI_MAXSERV];
	bool debug = wget_logger_is_active(wget_get_logger(WGET_LOGGER_DEBUG));

	if (unlikely(!tcp))
		return WGET_E_INVALID;

	wget_dns_freeaddrinfo(tcp->dns, &tcp->addrinfo);
	xfree(tcp->host);

	tcp->addrinfo = wget_dns_resolve(tcp->dns, host, port, tcp->family, tcp->preferred_family, WGET_TCP_CONNECTION);
	tcp->remote_port = port;

	for (ai = tcp->addrinfo; ai; ai = ai->ai_next) {
		// Skip non-TCP sockets
		if (ai->ai_socktype != SOCK_STREAM)
			continue;

		if (debug)
			debug_addr("trying", ai->ai_addr, ai->ai_addrlen);

		int sockfd;
		if ((sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) != -1) {
			_set_async(sockfd);
			set_socket_options(tcp, sockfd);

			if (tcp->bind_addrinfo) {
				if (debug)
					debug_addr("binding to",
						   tcp->bind_addrinfo->ai_addr, tcp->bind_addrinfo->ai_addrlen);

				if (bind(sockfd, tcp->bind_addrinfo->ai_addr, tcp->bind_addrinfo->ai_addrlen) != 0) {
					print_error_host(_("Failed to bind"), host);
					close(sockfd);

					return WGET_E_UNKNOWN;
				}
			}

			rc = tcp_connect(tcp, ai, sockfd);
			if (rc < 0
				&& errno != EAGAIN
				&& errno != EINPROGRESS
			) {
				print_error_host(_("Failed to connect"), host);
				ret = WGET_E_CONNECT;
				close(sockfd);
			} else {
				tcp->sockfd = sockfd;
				if (tcp->ssl) {
					if ((ret = wget_ssl_open(tcp))) {
						if (ret == WGET_E_CERTIFICATE) {
							wget_tcp_close(tcp);
							break; /* stop here - the server cert couldn't be validated */
						}

						/* do not free tcp->addrinfo when calling wget_tcp_close() */
						struct addrinfo *ai_tmp = tcp->addrinfo;

						tcp->addrinfo = NULL;
						wget_tcp_close(tcp);
						tcp->addrinfo = ai_tmp;

						continue;
					}
				}

				if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
						adr, sizeof(adr), s_port, sizeof(s_port), NI_NUMERICHOST | NI_NUMERICSERV) == 0)
					tcp->ip = wget_strdup(adr);
				else
					tcp->ip = NULL;

				tcp->host = wget_strdup(host);

				return WGET_E_SUCCESS;
			}
		} else
			print_error_host(_("Failed to create socket"), host);
	}

	return ret;
}

/**
 * \param[in] tcp An active connection.
 * \return WGET_E_SUCCESS (0) on success, or a negative integer on error (one of WGET_E_XXX, defined in `<wget.h>`).
 * Start TLS for this connection.
 *
 * This will typically be called by wget_tcp_accept().
 *
 * If the socket is listening (e.g. wget_tcp_listen(), wget_tcp_accept()), it will expect the client to perform a TLS handshake,
 * and fail if it doesn't.
 *
 * If this is a client connection (e.g. wget_tcp_connect()), it will try perform a TLS handshake with the server.
 */
int wget_tcp_tls_start(wget_tcp *tcp)
{
	return wget_ssl_open(tcp);
}

/**
 * \param[in] tcp An active connection.
 *
 * Stops TLS, but does not close the connection. Data will be transmitted in the clear from now on.
 */
void wget_tcp_tls_stop(wget_tcp *tcp)
{
	if (tcp)
		wget_ssl_close(&tcp->ssl_session);
}

/**
 * \param[in] tcp An active TCP connection.
 * \param[in] buf Destination buffer, at least \p count bytes long.
 * \param[in] count Length of the buffer \p buf.
 * \return Number of bytes read
 *
 * Read \p count bytes of data from the TCP connection represented by \p tcp
 * and store them in the buffer \p buf.
 *
 * This function knows whether the provided connection is over TLS or not
 * and it will do the right thing.
 *
 * The `tcp->timeout` parameter is taken into account by this function as well.
 * It specifies how long should this function wait until there's data available
 * to read (in milliseconds). The default timeout is -1, which means to wait indefinitely.
 *
 * The following two values are special:
 *
 *  - `0`: No timeout, immediate.
 *  - `-1`: Infinite timeout. Wait indefinitely until a new connection comes.
 *
 * You can set the timeout with wget_tcp_set_timeout().
 *
 * In particular, the returned value will be zero if no data was available for reading
 * before the timeout elapsed.
 */
ssize_t wget_tcp_read(wget_tcp *tcp, char *buf, size_t count)
{
	ssize_t rc;

	if (unlikely(!tcp || !buf))
		return 0;

	if (tcp->ssl_session) {
		rc = wget_ssl_read_timeout(tcp->ssl_session, buf, count, tcp->timeout);
	} else {
		if (tcp->timeout) {
			if ((rc = wget_ready_2_read(tcp->sockfd, tcp->timeout)) <= 0)
				return rc;
		}

		rc = recvfrom(tcp->sockfd, buf, count, 0, NULL, NULL);
	}

	if (rc < 0)
		error_printf(_("Failed to read %zu bytes (hostname='%s', ip=%s, errno=%d)\n"),
			count, tcp->host, tcp->ip, errno);

	return rc;
}

/**
 * \param[in] tcp An active TCP connection.
 * \param[in] buf A buffer, at least \p count bytes long.
 * \param[in] count Number of bytes from \p buf to send through \p tcp.
 * \return The number of bytes written, or -1 on error.
 *
 * Write \p count bytes of data from the buffer \p buf to the TCP connection
 * represented by \p tcp.
 *
 * This function knows whether the provided connection is over TLS or not
 * and it will do the right thing.
 *
 * TCP Fast Open will be used if it's available and enabled. You can enable TCP Fast Open
 * with wget_tcp_set_tcp_fastopen().
 *
 * This function honors the `timeout` parameter. If the write operation fails because the socket buffer is full,
 * then it will wait at most that amount of milliseconds. If after the timeout the socket is still unavailable
 * for writing, this function returns zero.
 *
 * The following two values are special:
 *
 *  - `0`: No timeout. The socket must be available immediately.
 *  - `-1`: Infinite timeout. Wait indefinitely until the socket becomes available.
 *
 * You can set the timeout with wget_tcp_set_timeout().
 */
ssize_t wget_tcp_write(wget_tcp *tcp, const char *buf, size_t count)
{
	ssize_t nwritten = 0;

	if (unlikely(!tcp || !buf))
		return -1;

	if (tcp->ssl_session)
		return wget_ssl_write_timeout(tcp->ssl_session, buf, count, tcp->timeout);

	while (count) {
		ssize_t n;

#ifdef TCP_FASTOPEN_LINUX
		if (tcp->tcp_fastopen && tcp->first_send) {
			n = sendto(tcp->sockfd, buf, count, MSG_FASTOPEN,
				tcp->connect_addrinfo->ai_addr, tcp->connect_addrinfo->ai_addrlen);
			tcp->first_send = 0;

			if (n < 0 && errno == EOPNOTSUPP) {
				/* fallback from fastopen, e.g. when fastopen is disabled in system */
				tcp->tcp_fastopen = 0;

				int rc = connect(tcp->sockfd, tcp->connect_addrinfo->ai_addr, tcp->connect_addrinfo->ai_addrlen);
				if (rc < 0
					&& errno != EAGAIN
					&& errno != ENOTCONN
					&& errno != EINPROGRESS)
				{
					print_error(tcp, _("Failed to connect"));
					return -1;
				}
				errno = EAGAIN;
			}
		} else
#endif
			n = send(tcp->sockfd, buf, count, 0);

		if (n >= 0) {
			nwritten += n;

			if ((size_t)n >= count)
				return nwritten;

			count -= n;
			buf += n;
		} else {
			if (errno != EAGAIN
				&& errno != ENOTCONN
				&& errno != EINPROGRESS)
			{
				error_printf(_("Failed to send %zu bytes (hostname='%s', ip=%s, errno=%d)\n"),
					count, tcp->host, tcp->ip, errno);
				return -1;
			}

			if (tcp->timeout) {
				int rc = wget_ready_2_write(tcp->sockfd, tcp->timeout);
				if (rc <= 0)
					return rc;
			}
		}
	}

	return 0;
}

/**
 * \param[in] tcp An active TCP connection.
 * \param[in] fmt Format string (like in `printf(3)`).
 * \param[in] args `va_args` argument list (like in `vprintf(3)`)
 *
 * Write data in vprintf-style format, to the connection \p tcp.
 *
 * It uses wget_tcp_write().
 */
ssize_t wget_tcp_vprintf(wget_tcp *tcp, const char *fmt, va_list args)
{
	char sbuf[4096];
	wget_buffer buf;
	ssize_t len2;

	wget_buffer_init(&buf, sbuf, sizeof(sbuf));
	wget_buffer_vprintf(&buf, fmt, args);

	len2 = wget_tcp_write(tcp, buf.data, buf.length);

	wget_buffer_deinit(&buf);

	if (len2 > 0)
		debug_write(buf.data, len2);

	if (len2 > 0 && (ssize_t) buf.length != len2)
		error_printf(_("%s: internal error: length mismatch %zu != %zd\n"), __func__, buf.length, len2);

	return len2;
}

/**
 * \param[in] tcp An active TCP connection.
 * \param[in] fmt Format string (like in `printf(3)`).
 *
 * Write data in printf-style format, to the connection \p tcp.
 *
 * It uses wget_tcp_vprintf(), which in turn uses wget_tcp_write().
 */
ssize_t wget_tcp_printf(wget_tcp *tcp, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	ssize_t len = wget_tcp_vprintf(tcp, fmt, args);
	va_end(args);

	return len;
}

/**
 * \param[in] tcp An active TCP connection
 *
 * Close a TCP connection.
 */
void wget_tcp_close(wget_tcp *tcp)
{
	if (likely(tcp)) {
		wget_tcp_tls_stop(tcp);
		if (tcp->sockfd != -1) {
			close(tcp->sockfd);
			tcp->sockfd = -1;
		}
		wget_dns_freeaddrinfo(tcp->dns, &tcp->addrinfo);
		xfree(tcp->host);
	}
}

/** @} */

/* wget_quic getter and setter functions */

void
wget_quic_add_stream (wget_quic *quic, wget_quic_stream *stream)
{
  wget_list_append (quic->streams, stream, sizeof(stream));
}

wget_quic_stream *
wget_quic_find_stream (wget_quic *quic, int64_t stream_id)
{
  for (void *l = (void *)wget_quic_get_streams(quic) + 1; l; l = wget_list_getnext(l))
    {
      wget_quic_stream *stream = (wget_quic_stream *)l;
	  //Stream_get_id is not very good name. Write getter and setter functions for Stream as well.
      if (stream_get_id (stream) == stream_id)
        return stream;
    }
  return NULL;
}

ngtcp2_conn *
wget_quic_get_ngtcp2_conn (wget_quic *quic)
{
  return quic->conn;
}

wget_list* wget_quic_get_streams(wget_quic *quic)
{
	return quic->streams;
}

void
wget_quic_set_ngtcp2_conn (wget_quic *quic, ngtcp2_conn *conn)
{
  quic->conn = conn;
}

int
wget_quic_get_socket_fd (wget_quic *quic)
{
  return quic->sockfd;
}

void
wget_quic_set_socket_fd (wget_quic *quic, int socketfd)
{
  quic->sockfd = socketfd;
}

int
wget_quic_get_timer_fd (wget_quic *quic)
{
  return quic->timerfd;
}

struct sockaddr *
wget_quic_get_local_addr (wget_quic *quic, size_t *local_addrlen)
{
  *local_addrlen = quic->local->size;
  return quic->local->addr;
}

void
wget_quic_set_local_addr (wget_quic *quic,
                           struct sockaddr *local_addr,
                           size_t local_addrlen)
{
  memcpy (quic->local->addr, local_addr, local_addrlen);
  quic->local->size = local_addrlen;
}

void
wget_quic_set_remote_addr (wget_quic *quic,
                           struct sockaddr *remote_addr,
                           size_t remote_addrlen)
{
  memcpy (quic->remote->addr, remote_addr, remote_addrlen);
  quic->remote->size = remote_addrlen;
}

void *
wget_quic_get_ssl_session(wget_quic *quic)
{
	return quic->ssl_session;
}

void
wget_quic_set_ssl_session(wget_quic *quic, void *session)
{	
	quic->ssl_session = session;
}

/* wget_quic_stream getter and setter and utlitly functions [Only Required Implemented as of Now] */
int64_t 
wget_quic_stream_get_id(wget_quic_stream *stream)
{
	return stream->id;
}

void
wget_quic_stream_mark_acked (wget_quic_stream *stream, size_t offset)
{
  while (!wget_queue_is_empty (stream->buffer))
    {
      stream_byte *head  = wget_queue_peek (stream->buffer);
      if (stream->ack_offset + stream_byte_get_size (head) > offset)
        break;

      stream->ack_offset += stream_byte_get_size (head);
      head = stream_queue_dequeue (stream->buffer);
    }
}

/*

Structs present : 

Struct similar to GBytes.
A node of this struct is pushed to the GQueue which is present in the struct Stream
This struct Stream is appended in the Glist present in the struct Connection. 

Implementations : 
1. Standard Implementation of Bytes, Generic Queue and Generic List.
2. All the standard functions for accessing all these structures.

*/

//Bytes Implementation.
//Apperently as per my observation, there is a ref count in the stream_byte.
//This should handle duplicate data. Not yet handled in the implementation.
typedef struct
{
	unsigned char* data;
	size_t size;
}stream_byte;

stream_byte *stream_byte_new(const unsigned char *data, size_t size)
{
	stream_byte *bytes = wget_malloc(sizeof(stream_byte));
	if (bytes){
		bytes->data = wget_malloc(size);
		if (!bytes->data){
			xfree(bytes->data);
			return NULL;
		}
		memcpy((void *)bytes->data, data, size);
		bytes->size = size;
	}
	return bytes;
}

size_t stream_byte_get_size(const stream_byte *bytes)
{
	return bytes->size;
}

const unsigned char *stream_byte_get_data(const stream_byte* bytes)
{
	return bytes->data;
}

void stream_byte_free(stream_byte *bytes)
{
	xfree(bytes->data);
	xfree(bytes);
}

/* Helper Function for Setting quic_connect */
uint64_t
timestamp (void)
{
  struct timespec tp;

  if (clock_gettime (CLOCK_MONOTONIC, &tp) < 0)
    return 0;

  return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

/* Callback functions for ngtcp2 */
static int
recv_stream_data_cb (ngtcp2_conn *conn __attribute__((unused)),
		     uint32_t flags __attribute__((unused)),
		     int64_t stream_id,
                     uint64_t offset __attribute__((unused)),
		     const uint8_t *data, size_t datalen,
                     void *user_data __attribute__((unused)),
		     void *stream_user_data __attribute__((unused)))
{
  write (STDOUT_FILENO, data, datalen);
  return 0;
}

static int
acked_stream_data_offset_cb (ngtcp2_conn *conn __attribute__((unused)),
			     int64_t stream_id,
                             uint64_t offset, uint64_t datalen,
                             void *user_data,
			     void *stream_user_data __attribute__((unused)))
{
  wget_quic *connection = user_data;
  wget_quic_stream *stream = wget_quic_find_stream (connection, stream_id);
  if (stream)
    wget_quic_stream_mark_acked (stream, offset + datalen);
  return 0;
}

static const ngtcp2_callbacks callbacks = 
{
    /* Use the default implementation from ngtcp2_crypto */
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,

	/*These callback functions implemented in same file above*/
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_stream_data = recv_stream_data_cb,
	/*These both functions are present in the ssl_gnutls.c*/
    .rand = rand_cb,
    .get_new_connection_id = get_new_connection_id_cb,
};

#define BUF_SIZE 1280

ssize_t send_packet(int fd, const uint8_t *data, size_t data_size,
		    struct sockaddr *remote_addr, size_t remote_addrlen)
{
	struct iovec iov;
	iov.iov_base = (void *)data;
	iov.iov_len = data_size;

	struct msghdr msg;
	memset (&msg, 0, sizeof(msg));
	msg.msg_name = remote_addr;
	msg.msg_namelen = remote_addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t ret;

	do
		ret = sendmsg (fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	return ret;
}

ssize_t recv_packet(int fd, uint8_t *data, size_t data_size,
		    struct sockaddr *remote_addr, size_t *remote_addrlen)
{
	struct iovec iov;
	iov.iov_base = data;
	iov.iov_len = data_size;

	struct msghdr msg;
	memset (&msg, 0, sizeof(msg));

	msg.msg_name = remote_addr;
	msg.msg_namelen = *remote_addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t ret;

	do
		ret = recvmsg(fd, &msg, MSG_DONTWAIT);
	while (ret < 0 && errno == EINTR);

	*remote_addrlen = msg.msg_namelen;

	return ret;
}

static int handshake_write(wget_quic *quic)
{
	int ret;
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize n_read, n_written;
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_vec datav;
	ngtcp2_conn *conn = wget_quic_get_ngtcp2_conn(quic);
	int64_t stream_id = -1;
	uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
	uint64_t ts = timestamp();

	ngtcp2_path_storage_zero(&ps);

	datav.base = NULL;
	datav.len = 0;

	n_written = ngtcp2_conn_writev_stream(conn, &ps.path, &pi,
					      buf, sizeof(buf),
					      &n_read,
					      flags,
					      stream_id,
					      &datav, 1,
					      ts);
	if (n_written < 0) {
		error_printf("ERROR: ngtcp2_conn_writev_stream: %s\n",
			ngtcp2_strerror((int) n_written));
		return WGET_E_INVALID;
	}

	if (n_written == 0)
		return WGET_E_SUCCESS;

	ret = send_packet(wget_quic_get_socket_fd(quic), buf, n_written,
			  NULL, 0);
	if (ret < 0) {
		error_printf("ERROR: send_packet: %s\n", strerror(errno));
		return WGET_E_INVALID;
	}

	return WGET_E_SUCCESS;
}

static int handshake_read(wget_quic *quic)
{
	uint8_t buf[BUF_SIZE];
	ngtcp2_ssize ret;
	ngtcp2_path path;
	ngtcp2_pkt_info pi;
	struct sockaddr_storage remote_addr;
	size_t remote_addrlen = sizeof(remote_addr);
	int socket_fd = wget_quic_get_socket_fd(quic);
	ngtcp2_conn *conn = wget_quic_get_ngtcp2_conn(quic);

	for (;;) {
		remote_addrlen = sizeof(remote_addr);

		ret = recv_packet(socket_fd, buf, sizeof(buf),
				  (struct sockaddr *) &remote_addr, &remote_addrlen);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			error_printf("ERROR: recv_packet: %s\n", strerror(errno));
			return WGET_E_UNKNOWN;
		}

		memcpy(&path, ngtcp2_conn_get_path(conn), sizeof(path));
		path.remote.addrlen = remote_addrlen;
		path.remote.addr = (struct sockaddr *) &remote_addr;

		ret = ngtcp2_conn_read_pkt(conn,
					   &path, &pi, buf, ret, timestamp());
		if (ret < 0) {
			error_printf("ERROR: ngtcp2_conn_read_pkt: %s\n",
				ngtcp2_strerror(ret));
			return WGET_E_UNKNOWN;
		}
	}
}

int quic_handshake(wget_quic_client* cli){
	int ret,
	timer_fd = wget_quic_get_timer_fd(cli->quic);
	ngtcp2_conn *conn = wget_quic_get_ngtcp2_conn(cli->quic);
	ngtcp2_tstamp expiry, now;
	struct itimerspec it;

	while (!ngtcp2_conn_get_handshake_completed(conn)){
		if ((ret = handshake_write(cli->quic)) < 0){
			return ret;
		}

		expiry = ngtcp2_conn_get_expiry(conn);
		now = timestamp();
		ret = timerfd_settime(timer_fd, 0, &it, NULL);
		if (ret < 0) {
			fprintf(stderr, "ERROR: timerfd_settime: %s", strerror(errno));
			return WGET_E_TIMEOUT;
		}
		if (expiry < now) {
			it.it_value.tv_sec = 0;
			it.it_value.tv_nsec = 1;
		} else {
			it.it_value.tv_sec = (expiry - now) / NGTCP2_SECONDS;
			it.it_value.tv_nsec = ((expiry - now) % NGTCP2_SECONDS) / NGTCP2_NANOSECONDS;
		}

		ret = timerfd_settime(timer_fd, 0, &it, NULL);
		if (ret < 0) {
			fprintf(stderr, "ERROR: timerfd_settime: %s", strerror(errno));
			return WGET_E_TIMEOUT;
		}
		handshake_read(cli->quic);
	}
	return 0;
}

/**
 * \param[in] cli A `wget_quic_client` structure representing a QUIC client.
 * \param[in] host Hostname or IP to connect to.
 * \param[in] port Port Number.
 * 
 * Dubug is not used as of now as used in the wget_tcp_connect
*/

int wget_quic_connect(wget_quic_client *cli, const char *host, uint16_t port)
{
	wget_quic* quic = cli->quic;
	struct addrinfo *ai_rp;
	int ret ,rc;

	if (unlikely(!quic))
		return WGET_E_INVALID;

	wget_dns_freeaddrinfo(quic->dns, &quic->addrinfo);
	xfree(quic->host);

	quic->addrinfo = wget_dns_resolve(quic->dns, host, port, quic->family, quic->preferred_family, WGET_QUIC_CONNECTION);
	
	for (ai_rp = quic->addrinfo ; ai_rp != NULL ; ai_rp = ai_rp->ai_next){
		int sockfd;
		if ((sockfd = socket(ai_rp->ai_family, ai_rp->ai_socktype | SOCK_NONBLOCK, ai_rp->ai_protocol) != -1)){
			_set_async(sockfd);
			if (quic->bind_addrinfo) {
				if(bind(sockfd, quic->bind_addrinfo->ai_addr, quic->bind_addrinfo->ai_addrlen) != 0) {
					print_error_host(_("Failed to bind"), host);
					close(sockfd);
					return WGET_E_UNKNOWN;
				}
			}
			rc = connect(sockfd, ai_rp->ai_addr, ai_rp->ai_addrlen);
			if (rc < 0 && errno != EAGAIN && errno != EINPROGRESS) {
				print_error_host(_("Failed to connect"), host);
				ret = WGET_E_CONNECT;
				close(sockfd);
			} else {
				wget_quic_set_socket_fd(quic, sockfd);
				ret = wget_ssl_quic_open(quic);
				if (ret == WGET_E_CERTIFICATE){
					/*
						Write a function similar to 
						wget_tcp_close which basically
						deinitialises the function.
					*/
					break;
				}
				getsockname(sockfd, quic->local->addr, (socklen_t *)&quic->local->size);

				ngtcp2_path path =
				{
					.local = {
						.addrlen = quic->local->size,
						.addr = quic->local->addr,
					},
					.remote = {
						.addrlen = ai_rp->ai_addrlen,
						.addr = ai_rp->ai_addr,
					}
				};

				ngtcp2_settings settings;
				ngtcp2_settings_default (&settings);
				settings.initial_ts = timestamp ();
				/*
					Not sure what to do with this log_printf function.
				*/
				settings.log_printf = log_printf;

				ngtcp2_transport_params params;
				ngtcp2_transport_params_default (&params);
				params.initial_max_streams_uni = 3;
				params.initial_max_stream_data_bidi_local = 128 * 1024;
				params.initial_max_data = 1024 * 1024;

				ngtcp2_cid scid, dcid;
				if (get_random_cid (&scid) < 0 || get_random_cid (&dcid) < 0)
					error (EXIT_FAILURE, EINVAL, "get_random_cid failed\n");

				ngtcp2_conn *conn = NULL;
				ret = ngtcp2_conn_client_new (&conn, &dcid, &scid, &path,
							NGTCP2_PROTO_VER_V1,
							&callbacks, &settings, &params, NULL,
							quic);
				if (ret < 0){
					print_error_host(_("Failed to create a QUIC client"), host);
					ret = WGET_E_CONNECT;
					close(sockfd);
				}
				
				wget_quic_set_ngtcp2_conn(quic, conn);					
				wget_quic_set_remote_addr(quic, ai_rp->ai_addr, ai_rp->ai_addrlen);
				wget_ssl_quic_setup(quic->ssl_session, quic->conn);
				quic->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
				if (quic->timerfd < 0){
					print_error_host(_("Timerfd Failed"), host);
					ret = WGET_E_UNKNOWN;
					close(sockfd);
				}
				if ((ret = quic_handshake(cli)) < 0){
					return ret;
				}
				return WGET_E_SUCCESS;
			}
		} else {
			print_error_host(_("Failed to create socket"), host);
			ret = WGET_E_UNKNOWN;
		}
	}
	return ret;
}

/*
QUIC protocol integration with wget2 library.
Initial Implemenations :

wget_quic_connect
wget_quic_read
wget_quic_write

*/