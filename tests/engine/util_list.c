// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_list.h"
#include "util_mutex.h"

/**
 * struct node - Node of a linked list.
 * @id: Local ID of the data. Comes from test definition file.
 * @data: Buffer containing the data stored by the node.
 * @next: Pointer to next node.
 */
struct node {
	unsigned int id;
	void *data;
	struct node *next;
};

static int list_add_node(struct llist *list, unsigned int id, void *data,
			 int lock)
{
	int res;
	struct node *last = NULL;
	struct node *node;

	if (!list)
		return ERR_CODE(BAD_ARGS);

	if (lock)
		util_mutex_lock(list->lock);

	node = malloc(sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	node->id = id;
	node->data = data;
	node->next = NULL;

	/* New node is the last of the list */
	last = list->head;
	if (!last) {
		list->head = node;
	} else {
		while (last->next)
			last = last->next;

		last->next = node;
	}

	res = ERR_CODE(PASSED);

exit:
	if (lock)
		util_mutex_unlock(list->lock);

	return res;
}

static int list_find_node(struct llist *list, unsigned int id, void **data,
			  int lock)
{
	struct node *node;

	if (!list || !data)
		return ERR_CODE(BAD_ARGS);

	if (lock)
		util_mutex_lock(list->lock);

	node = list->head;

	while (node) {
		if (node->id == id) {
			*data = node->data;
			break;
		}
		node = node->next;
	}

	if (lock)
		util_mutex_unlock(list->lock);

	return ERR_CODE(PASSED);
}

int util_list_init(struct llist **list, void (*free)(void *))
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	*list = malloc(sizeof(struct llist));
	if (!*list) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	(*list)->head = NULL;
	(*list)->free = free;

	/* List protector */
	(*list)->lock = util_mutex_create();
	if (!(*list)->lock)
		return ERR_CODE(FAILED);

	return ERR_CODE(PASSED);
}

int util_list_clear(struct llist *list)
{
	int res;
	struct node *head = NULL;
	struct node *next = NULL;

	if (!list)
		return ERR_CODE(PASSED);

	util_mutex_lock(list->lock);
	head = list->head;

	while (head) {
		next = head;
		head = head->next;
		if (next->data && list->free)
			list->free(next->data);
		free(next);
	}

	util_mutex_unlock(list->lock);
	res = util_mutex_destroy(list->lock);

	if (res == ERR_CODE(PASSED))
		free(list);

	return res;
}

int util_list_add_node(struct llist *list, unsigned int id, void *data)
{
	return list_add_node(list, id, data, 1);
}

int util_list_add_node_nl(struct llist *list, unsigned int id, void *data)
{
	return list_add_node(list, id, data, 0);
}

int util_list_find_node(struct llist *list, unsigned int id, void **data)
{
	return list_find_node(list, id, data, 1);
}

struct node *util_list_next(struct llist *list, struct node *node,
			    unsigned int *id)
{
	struct node *next;

	if (!list)
		return NULL;

	if (!node)
		next = list->head;
	else
		next = node->next;

	if (next && id)
		*id = next->id;

	return next;
}

void *util_list_data(struct node *node)
{
	if (!node)
		return NULL;

	return node->data;
}

void util_list_lock(struct llist *list)
{
	if (list)
		util_mutex_lock(list->lock);
}

void util_list_unlock(struct llist *list)
{
	if (list)
		util_mutex_unlock(list->lock);
}
