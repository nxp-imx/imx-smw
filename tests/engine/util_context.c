// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_context.h"

int util_context_add_node(struct llist **list, unsigned int id,
			  struct smw_op_context *smw_context)
{
	int res = ERR_CODE(PASSED);

	if (!list)
		return ERR_CODE(BAD_ARGS);

	if (!*list)
		res = util_list_init(list, NULL);

	if (res == ERR_CODE(PASSED))
		res = util_list_add_node(*list, id, smw_context);

	return res;
}

int util_context_find_node(struct llist *list, unsigned int id,
			   struct smw_op_context **smw_context)
{
	if (!list || !smw_context)
		return ERR_CODE(BAD_ARGS);

	*smw_context = util_list_find_node(list, id);

	if (!*smw_context)
		return ERR_CODE(FAILED);

	return ERR_CODE(PASSED);
}
