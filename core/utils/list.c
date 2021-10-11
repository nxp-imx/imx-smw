// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "list.h"

#include "common.h"

static struct node *create_node(void *data, unsigned int ref,
				void (*printer)(void *))
{
	struct node *node = SMW_UTILS_MALLOC(sizeof(*node));

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (node) {
		node->prev = NULL;
		node->next = NULL;

		node->printer = printer;
		node->ref = ref;
		node->data = data;
	}

	return node;
}

static void destroy_node(struct node *node)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (node->data)
		SMW_UTILS_FREE(node->data);

	SMW_UTILS_FREE(node);
}

void smw_utils_list_init(struct smw_utils_list *list)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	list->first = NULL;
	list->last = NULL;
}

void smw_utils_list_destroy(struct smw_utils_list *list)
{
	struct node *next, *node = list->first;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (node) {
		next = node->next;
		destroy_node(node);
		node = next;
	}

	smw_utils_list_init(list);
}

bool smw_utils_list_append_data(struct smw_utils_list *list, void *data,
				unsigned int ref, void (*printer)(void *))
{
	struct node *node = create_node(data, ref, printer);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!node)
		return false;

	if (list->last) {
		list->last->next = node;
		node->prev = list->last;
		list->last = node;
	} else {
		SMW_DBG_ASSERT(!list->first);
		list->first = node;
		list->last = node;
	}

	return true;
}

static struct node *find_node(struct node *node, unsigned int ref)
{
	struct node *next = node;

	while (next) {
		if (next->ref == ref)
			break;
		next = next->next;
	}

	return next;
}

struct node *smw_utils_list_find_first(struct smw_utils_list *list,
				       unsigned int *ref)
{
	struct node *next;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!list)
		return NULL;

	next = list->first;

	if (ref)
		next = find_node(next, *ref);

	return next;
}

struct node *smw_utils_list_find_next(struct node *node, unsigned int *ref)
{
	struct node *next;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!node)
		return NULL;

	next = node->next;

	if (ref)
		next = find_node(next, *ref);

	return next;
}

unsigned int smw_utils_list_get_ref(struct node *node)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!node)
		return (-1);

	return node->ref;
}

void *smw_utils_list_get_data(struct node *node)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!node)
		return NULL;

	return node->data;
}

__weak void smw_utils_list_print(struct smw_utils_list *list)
{
	(void)list;
}
