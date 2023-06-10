/*
 * Copyright (c) 2015 Tim Ruehsen
 * Copyright (c) 2015-2022 Free Software Foundation, Inc.
 *
 * This file is part of libwget.
 *
 * Libwget is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Libwget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Libwget.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Header file for private net structures
 *
 * Changelog
 * 23.02.2015  Tim Ruehsen
 *
 */

#ifndef LIBWGET_NET_H
# define LIBWGET_NET_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <netdb.h>

struct wget_tcp_st {
	void *
		ssl_session;
	struct addrinfo *
		addrinfo;
	struct addrinfo *
		bind_addrinfo;
	struct addrinfo *
		connect_addrinfo; // needed for TCP_FASTOPEN delayed connect
	const char
		*host,
		*ssl_hostname, // if set, do SSL hostname checking
		*ip,
		*bind_interface;
	wget_dns
		*dns;
	int
		sockfd,
		// timeouts in milliseconds
		// there is no real 'connect timeout', since connects are async
		dns_timeout,
		connect_timeout,
		timeout, // read and write timeouts are the same
		family,
		preferred_family,
		protocol; // WGET_PROTOCOL_HTTP1_1, WGET_PROTOCOL_HTTP2_0
	wget_hpkp_stats_result
		hpkp; // hpkp stats
	uint16_t
		remote_port; // needed for not yet connected situations (e.g. DANE)
	bool
		ssl : 1,
		tls_false_start : 1,
		tcp_fastopen : 1, // do we use TCP_FASTOPEN or not
		first_send : 1; // TCP_FASTOPEN's first packet is sent different
};

typedef struct{
	struct sockaddr *addr;
	size_t size;
}info_addr;

typedef struct{
	int64_t id;
	wget_queue *buffer;
	size_t sent_offset;
	size_t ack_offset;
}wget_quic_stream_st;

struct wget_quic_st{
	void
		*ssl_session;
	ngtcp2_conn
		*conn;
	int
		sockfd,
		timerfd,
		family,
		preferred_family,
		protocol,
		connect_timeout;
	info_addr 
		*local,
		*remote;
	/* 
		Added this so as to accomodate with existing DNS function.
		Planning to go with this. Will replace the info_addr struct as and when the further code is edited.
	*/
	struct addrinfo
		*addrinfo,
		/*
			Explore options from where this is set.
			wget_tcp_set_bind_address func in net.c
			have that function generalised for connection type.
		*/
		*bind_addrinfo;
	wget_list
		*streams;
	wget_dns
		*dns;
	const char
		*host,
		*ssl_hostname;
	bool
		is_closed;
	uint16_t
		remote_port;
};

typedef struct wget_quic_st wget_quic;
typedef wget_quic_stream_st wget_quic_stream;

#endif /* LIBWGET_NET_H */
