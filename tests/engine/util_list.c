// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_list.h"
#include "util_mutex.h"

/**
 * struct node - Node of a linked list.
 * @id: Local ID of the data.
 * @data: Buffer containing the data stored by the node.
 * @next: Pointer to next node.
 */
struct node {
	uintptr_t id;
	void *data;
	struct node *next;
};

static int write_id_uint(struct node *node, uintptr_t id)
{
	if (!node)
		return ERR_CODE(BAD_ARGS);

	node->id = id;

	return ERR_CODE(PASSED);
}

static int write_id_string(struct node *node, uintptr_t id)
{
	if (!node)
		return ERR_CODE(BAD_ARGS);

	node->id = (uintptr_t)malloc(strlen((const char *)id) + 1);
	if (!node->id) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strcpy((char *)node->id, (char *)id);

	return ERR_CODE(PASSED);
}

static void free_id_string(uintptr_t id)
{
	if (!id)
		free((void *)id);
}

static int match_id_uint(uintptr_t node_id, uintptr_t id)
{
	if ((unsigned int)id == (unsigned int)node_id)
		return 1;

	return 0;
}

static int match_id_string(uintptr_t id, uintptr_t node_id)
{
	if (!strcmp((char *)id, (char *)node_id))
		return 1;

	return 0;
}

static int list_add_node(struct llist *list, uintptr_t id, void *data, int lock)
{
	int res = ERR_CODE(BAD_ARGS);
	struct node *last = NULL;
	struct node *node;

	if (!list)
		return res;

	if (lock)
		util_mutex_lock(list->lock);

	node = calloc(1, sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE();
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	res = list->write_id(node, id);
	if (res != ERR_CODE(PASSED))
		goto exit;

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

exit:
	if (res != ERR_CODE(PASSED)) {
		if (node)
			free(node);
	}

	if (lock)
		util_mutex_unlock(list->lock);

	return res;
}

static int list_find_node(struct llist *list, uintptr_t id, void **data,
			  int lock)
{
	struct node *node;

	if (!list || !data)
		return ERR_CODE(BAD_ARGS);

	if (lock)
		util_mutex_lock(list->lock);

	node = list->head;

	while (node) {
		if (list->match_id(node->id, id)) {
			*data = node->data;
			break;
		}
		node = node->next;
	}

	if (lock)
		util_mutex_unlock(list->lock);

	return ERR_CODE(PASSED);
}

int util_list_init(struct llist **list, void (*free_data)(void *),
		   enum list_id_type id_type)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	*list = malloc(sizeof(struct llist));
	if (!*list) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	(*list)->head = NULL;
	(*list)->free_data = free_data;

	switch (id_type) {
	case LIST_ID_TYPE_UINT:
		(*list)->write_id = write_id_uint;
		(*list)->free_id = NULL;
		(*list)->match_id = match_id_uint;
		break;
	case LIST_ID_TYPE_STRING:
		(*list)->write_id = write_id_string;
		(*list)->free_id = free_id_string;
		(*list)->match_id = match_id_string;
		break;
	default:
		return ERR_CODE(BAD_ARGS);
	}

	/* List protector */
	(*list)->lock = util_mutex_create();
	if (!(*list)->lock)
		return ERR_CODE(FAILED);

	return ERR_CODE(PASSED);
}

int util_list_clear(struct llist *list)
{
	int res = ERR_CODE(PASSED);
	struct node *head = NULL;
	struct node *next = NULL;

	if (!list)
		return res;

	util_mutex_lock(list->lock);
	head = list->head;

	while (head) {
		next = head;
		head = head->next;
		if (list->free_data)
			list->free_data(next->data);
		if (list->free_id)
			list->free_id(next->id);
		free(next);
	}

	util_mutex_unlock(list->lock);
	res = util_mutex_destroy(&list->lock);

	if (res == ERR_CODE(PASSED))
		free(list);

	return res;
}

int util_list_add_node(struct llist *list, uintptr_t id, void *data)
{
	return list_add_node(list, id, data, 1);
}

int util_list_add_node_nl(struct llist *list, uintptr_t id, void *data)
{
	return list_add_node(list, id, data, 0);
}

int util_list_find_node(struct llist *list, uintptr_t id, void **data)
{
	return list_find_node(list, id, data, 1);
}

struct node *util_list_next(struct llist *list, struct node *node,
			    uintptr_t *id)
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
