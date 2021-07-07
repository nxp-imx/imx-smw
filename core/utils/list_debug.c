// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "list.h"

#include "common.h"

static void print_node(struct node *node)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Data: %p\n", node->data);
	if (node->printer)
		node->printer(node->data);
}

void smw_utils_list_print(struct smw_utils_list *list)
{
	struct node *node = list->first;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (SMW_DBG_LEVEL < SMW_DBG_LEVEL_DEBUG)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Print list: %p,\n"
		       "    first : %p,\n"
		       "    last  : %p\n",
		       list, list->first, list->last);

	while (node) {
		print_node(node);

		node = node->next;
	}
}
