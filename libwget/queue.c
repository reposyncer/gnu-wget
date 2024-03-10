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
 * Queue using linked list routines
 *
 */
#include <config.h>

#include <stdlib.h>
#include <string.h>

#include <wget.h>
#include "private.h"

struct wget_queue_st {
	struct wget_queue_node *head;
	struct wget_queue_node *tail;
};

wget_queue *wget_queue_init(void)
{
	wget_queue *queue = wget_malloc(sizeof(wget_queue));
	if (queue) {
		queue->head = NULL;
		queue->tail = NULL;
	}
	return queue;
}

void wget_queue_deinit(wget_queue *queue)
{
	if (queue) {
		wget_queue_node *fn = queue->head;
		wget_queue_node *next = queue->head;
		while (fn) {
			next = fn->next;
			xfree(fn);
			fn = next;
		}
		fn = NULL;
		next = NULL;
		xfree(queue);
	}
}

int
wget_queue_is_empty(wget_queue *queue)
{
	return(queue->head == NULL);
}

void*
wget_queue_enqueue(wget_queue *queue, const void *data)
{
	struct wget_queue_node *node = wget_malloc(sizeof(struct wget_queue_node));
	if (!node)
		return NULL;
	if (!data) {
		xfree(node);
		return NULL;
	}
	node->data = (void *)data;
	node->next = NULL;
	if (wget_queue_is_empty(queue)) {
		node->prev = NULL;
		queue->head = node;
		queue->tail = node;
	} else {
		node->prev = queue->tail;
		queue->tail->next = node;
		queue->tail = node;
	}

	return node + 1;
}

void*
wget_queue_dequeue(wget_queue *queue)
{
	if (wget_queue_is_empty(queue)) {
		return NULL;
	}

	struct wget_queue_node *node = queue->head;
	void *data = node->data;
	queue->head = queue->head->next;
	if (queue->head != NULL) {
		queue->head->prev = NULL;
	} else {
		queue->tail = NULL;
	}
	xfree(node);
	return data;
}

wget_byte *
wget_queue_peek(wget_queue *queue)
{
	if (wget_queue_is_empty(queue)) {
		return NULL;
	}
	return queue->head->data;
}

wget_byte *
wget_queue_peek_transmitted_node(wget_queue *queue)
{
	if (wget_queue_is_empty(queue))
		return NULL;

	wget_queue_node *temp = queue->head;
	while (temp) {
		wget_byte *data = (wget_byte *)(temp->data);
		if (wget_byte_get_transmitted(data) && wget_byte_get_type(data) == REQUEST_BYTE) {
			return data;
		}
		temp = temp->next;
	}

	return NULL;
}

wget_queue_node *
wget_queue_dequeue_transmitted_node(wget_queue *queue)
{
	if (wget_queue_is_empty(queue))
		return NULL;
	wget_queue_node *temp = queue->head;
	while (temp) {
		wget_byte *data = (wget_byte *)(temp->data);
		if (wget_byte_get_transmitted(data) && wget_byte_get_type(data) == REQUEST_BYTE) {
			if (temp->prev)
				temp->prev->next = temp->next;
			else
				queue->head = temp->next;

			if (temp->next)
				temp->next->prev = temp->prev;
			else
				queue->tail = temp->prev;

			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

wget_queue_node *
wget_queue_dequeue_data_node(wget_queue *queue)
{
	if (wget_queue_is_empty(queue))
		return NULL;
	wget_queue_node *temp = queue->head;
	while (temp) {
		wget_byte *data = (wget_byte *)(temp->data);
		if (!wget_byte_get_transmitted(data) && wget_byte_get_type(data) == RESPONSE_DATA_BYTE) {
			if (temp->prev)
				temp->prev->next = temp->next;
			else
				queue->head = temp->next;

			if (temp->next)
				temp->next->prev = temp->prev;
			else
				queue->tail = temp->prev;
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}

wget_byte *
wget_queue_peek_untransmitted_node(wget_queue *queue)
{
	if (wget_queue_is_empty(queue))
		return NULL;

	wget_queue_node *temp = queue->head;
	while (temp) {
		wget_byte *data = (wget_byte *)(temp->data);
		if (!wget_byte_get_transmitted(data) && wget_byte_get_type(data) == REQUEST_BYTE) {
			return data;
		}
		temp = temp->next;
	}

	return NULL;
}

void wget_queue_free_node(wget_queue_node *node,
	void (*data_free_func)(void *))
{
	if (node) {
		if (node->data && data_free_func)
			data_free_func(node->data);
		xfree(node);
	}
}
