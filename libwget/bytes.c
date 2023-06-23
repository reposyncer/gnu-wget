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
#include <string.h>

#include <wget.h>
#include "private.h"

typedef struct wget_byte_st {
	unsigned char* data;
	size_t size;
}wget_byte_st;

wget_byte *
wget_byte_new(const char *data, size_t size)
{
	wget_byte *bytes = wget_malloc(sizeof(wget_byte));
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

size_t 
wget_byte_get_size(const wget_byte *bytes)
{
	return bytes->size;
}

unsigned char *
wget_byte_get_data(const wget_byte* bytes)
{
	return bytes->data;
}

void 
wget_byte_free(wget_byte *bytes)
{
	xfree(bytes->data);
	xfree(bytes);
}