// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_context.h"

int util_context_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(FAILED);

	return util_list_init(list, NULL);
}

int util_context_add_node(struct llist *list, unsigned int id,
			  struct smw_op_context *smw_context)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_add_node(list, id, smw_context);
}

int util_context_find_node(struct llist *list, unsigned int id,
			   struct smw_op_context **smw_context)
{
	int res;

	if (!list || !smw_context)
		return ERR_CODE(BAD_ARGS);

	res = util_list_find_node(list, id, (void **)smw_context);
	if (res == ERR_CODE(PASSED) && !*smw_context)
		res = ERR_CODE(FAILED);

	return res;
}
