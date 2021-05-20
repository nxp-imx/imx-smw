// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_context.h"

int util_context_add_node(struct context_list **list, unsigned int id,
			  struct smw_op_context *smw_context)
{
	struct context_node *head = NULL;
	struct context_node *node;

	node = malloc(sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	node->id = id;
	node->smw_context = smw_context;
	node->next = NULL;

	if (!*list) {
		*list = malloc(sizeof(struct context_list));
		if (!*list) {
			free(node);
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		/* New context is the first of the list */
		(*list)->head = node;
	} else {
		head = (*list)->head;
		while (head->next)
			head = head->next;

		/* New context is the last of the list */
		head->next = node;
	}

	return ERR_CODE(PASSED);
}

void util_context_clear_list(struct context_list *list)
{
	struct context_node *head = NULL;
	struct context_node *del = NULL;

	if (!list)
		return;

	head = list->head;

	while (head) {
		del = head;
		head = head->next;
		if (del->smw_context)
			free(del->smw_context);
		free(del);
	}

	free(list);
}

int util_context_find_node(struct context_list *list, unsigned int id,
			   struct smw_op_context **smw_context)
{
	struct context_node *head = NULL;

	if (!list || !smw_context)
		return ERR_CODE(BAD_ARGS);

	head = list->head;

	while (head) {
		if (head->id == id) {
			*smw_context = head->smw_context;
			return ERR_CODE(PASSED);
		}

		head = head->next;
	}

	return ERR_CODE(FAILED);
}
