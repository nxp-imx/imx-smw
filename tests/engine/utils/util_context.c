// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2024 NXP
 */

#include <stdlib.h>

#include "util.h"
#include "util_context.h"

int util_context_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(FAILED);

	return util_list_init(list, NULL, LIST_ID_TYPE_UINT);
}

int util_context_add_node(struct llist *list, unsigned int id,
			  struct smw_op_context *smw_context)
{
	int res = ERR_CODE(BAD_ARGS);

	if (list)
		res = util_list_add_node(list, id, smw_context);

	if (res != ERR_CODE(PASSED))
		DBG_PRINT("Failed to add context node");

	return res;
}

int util_context_find_node(struct llist *list, unsigned int id,
			   struct smw_op_context **smw_context)
{
	int res = ERR_CODE(BAD_ARGS);

	if (!list || !smw_context)
		return res;

	res = util_list_find_node(list, id, (void **)smw_context);

	return res;
}

int util_context_update_node(struct llist *list, unsigned int id,
			     struct smw_op_context *context)
{
	int res = ERR_CODE(BAD_ARGS);

	if (!list)
		return res;

	res = util_list_update_node(list, id, (void *)context);
	if (res != ERR_CODE(PASSED))
		return res;

	return res;
}

int util_context_set_op_ctx(struct subtest_data *subtest, unsigned int *ctx_id,
			    struct smw_op_context **arg_context,
			    struct smw_op_context *api_ctx)
{
	int res = ERR_CODE(PASSED);

	/* Context ID is a mandatory parameter except for API tests */
	res = util_read_json_type(ctx_id, CTX_ID_OBJ, t_uint, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get operation context */
	if (*ctx_id != UINT_MAX) {
		res = util_context_find_node(list_op_ctxs(subtest), *ctx_id,
					     arg_context);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to find context node");
			return res;
		}
	} else {
		/* API specific tests cases */
		*arg_context = api_ctx;
	}

	return ERR_CODE(PASSED);
}
