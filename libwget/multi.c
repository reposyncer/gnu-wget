/*
 * Copyright (c) 2022 Free Software Foundation, Inc.
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
 * multi handle routines
 */

#include <config.h>

#include <wget.h>
#include "private.h"
#include "net.h"

struct wget_multi_st {
	wget_hashmap *
		tcps;
};

typedef struct wget_multi_st wget_multi;

WGET_GCC_PURE
static unsigned int hash_tcp(const wget_tcp *tcp)
{
	return (unsigned int) tcp->sockfd;
}

WGET_GCC_NONNULL_ALL WGET_GCC_PURE
static int compare_tcp(const wget_tcp *tcp1, const wget_tcp *tcp2)
{
	return tcp1->sockfd - tcp2->sockfd;
}

wget_multi *wget_multi_init(void)
{
	wget_multi *multi = wget_malloc(sizeof(wget_multi));

	if (multi) {
		multi->tcps = wget_hashmap_create(32, (wget_hashmap_hash_fn *) hash_tcp, (wget_hashmap_compare_fn *) compare_tcp);
	}

	return multi;
}

void wget_multi_deinit(wget_multi *multi)
{
	if (multi) {
		wget_hashmap_free(&multi->tcps);
		xfree(multi);
	}
}

void wget_multi_free(wget_multi **multi)
{
	if (multi) {
		wget_multi_deinit(*multi);
		xfree(*multi);
	}
}

int wget_multi_add(wget_multi *multi, wget_tcp *tcp)
{
	if (!multi || !tcp)
		return WGET_E_INVALID;

	return wget_hashmap_put(multi->tcps, tcp, NULL);
}

int wget_multi_remove(wget_multi *multi, wget_tcp *tcp)
{
	if (!multi || !tcp)
		return 0;

	return wget_hashmap_remove(multi->tcps, tcp);
}

struct fdset_data {
	fd_set *readfds;
	fd_set *writefds;
	int *nfds;
};

WGET_GCC_NONNULL_ALL
static int set_fd(void *_fdset_data, const void *_tcp, void *v)
{
	(void) v;
	struct fdset_data *fdset_data = _fdset_data;
	const wget_tcp *tcp = _tcp;
	int fd = tcp->sockfd;

	if (fd > *fdset_data->nfds)
		*fdset_data->nfds = fd;

	if (fdset_data->readfds)
		FD_SET(fd, fdset_data->readfds);

	if (fdset_data->writefds)
		FD_SET(fd, fdset_data->writefds);

	return 0;
}

int wget_multi_fdset(wget_multi *multi,
	fd_set *restrict readfds, fd_set *restrict writefds, fd_set *restrict exceptfds, int *nfds)
{
	(void)exceptfds;

	*nfds = 0;

	wget_hashmap_browse(multi->tcps, set_fd,
		&(struct fdset_data){.readfds = readfds, .writefds = writefds, .nfds = nfds});

	return WGET_E_SUCCESS;
}
