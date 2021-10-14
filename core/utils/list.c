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

static struct node *create_node(void *data, void (*printer)(void *))
{
	struct node *node = SMW_UTILS_MALLOC(sizeof(struct node));

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (node) {
		node->prev = NULL;
		node->next = NULL;

		node->printer = printer;
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

static struct node *find_node(struct smw_utils_list *list, void *filter,
			      bool (*match)(void *, void *))
{
	struct node *node = list->first;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (node) {
		if (match(node->data, filter))
			return node;

		node = node->next;
	}

	return NULL;
}

bool smw_utils_list_append_data(struct smw_utils_list *list, void *data,
				void (*printer)(void *))
{
	struct node *node = create_node(data, printer);

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

void *smw_utils_list_find_data(struct smw_utils_list *list, void *filter,
			       bool (*match)(void *, void *))
{
	struct node *node = find_node(list, filter, match);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (node)
		return node->data;

	return NULL;
}

__weak void smw_utils_list_print(struct smw_utils_list *list)
{
	(void)list;
}
