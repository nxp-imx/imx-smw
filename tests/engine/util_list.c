// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_list.h"

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

int util_list_init(struct llist **list, void (*free)(void *))
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	*list = malloc(sizeof(struct llist));
	if (!*list) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	(*list)->head = NULL;
	(*list)->free = free;

	return ERR_CODE(PASSED);
}

int util_list_add_node(struct llist *list, unsigned int id, void *data)
{
	struct node *last = NULL;
	struct node *node;

	node = malloc(sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
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

	return ERR_CODE(PASSED);
}

void util_list_clear(struct llist *list)
{
	struct node *head = NULL;
	struct node *next = NULL;

	if (!list)
		return;

	head = list->head;

	while (head) {
		next = head;
		head = head->next;
		if (next->data && list->free)
			list->free(next->data);
		free(next);
	}

	free(list);
}

void *util_list_find_node(struct llist *list, unsigned int id)
{
	struct node *node;

	if (!list)
		return NULL;

	node = list->head;

	while (node) {
		if (node->id == id)
			return node->data;

		node = node->next;
	}

	return NULL;
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
