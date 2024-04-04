/*
 * Copyright (c) 2023 Harshmohan Kulkarni
 * Copyright (c) 2015-2023 Free Software Foundation, Inc.
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
 * Bytes Implementation.
 *
 */

#include <config.h>

#include <stdlib.h>
#include <stdint.h> // uint8_t

#include <wget.h>
#include "private.h"

#define STATUS_INITIALISED 0
#define STATUS_SENT 1

typedef struct wget_byte_st {
	unsigned char *data;
	size_t size;
	int8_t status;
	int8_t type;
} wget_byte_st;

wget_byte *wget_byte_new(const char *data, size_t size, int8_t type)
{
	wget_byte *bytes = wget_malloc(sizeof(wget_byte));
	if (!bytes)
		return NULL;

	bytes->data = wget_memdup(data, size);
	if (!bytes->data){
		xfree(bytes);
		return NULL;
	}

	bytes->size = size;
	bytes->status = STATUS_INITIALISED;
	bytes->type = type;

	return bytes;
}

size_t wget_byte_get_size(const wget_byte *bytes)
{
	if (bytes)
		return bytes->size;

	return -1;
}

unsigned char *wget_byte_get_data(const wget_byte *bytes)
{
	if (bytes)
		return bytes->data;

	return NULL;
}

void wget_byte_free(wget_byte *bytes)
{
	xfree(bytes->data);
	xfree(bytes);
}

bool wget_byte_get_transmitted(wget_byte *bytes)
{
	if (bytes)
		return bytes->status != STATUS_INITIALISED;

	return true;
}

void wget_byte_set_transmitted(wget_byte *bytes)
{
	if (bytes)
		bytes->status = STATUS_SENT;
}

int8_t wget_byte_get_type(wget_byte *bytes)
{
	if (bytes)
		return bytes->type;

	return -1;
}

size_t wget_byte_get_struct_size(void)
{
	return sizeof(wget_byte);
}
