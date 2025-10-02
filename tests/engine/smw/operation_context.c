// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <smw_crypto.h>

#include "operation_context.h"
#include "util.h"
#include "util_cipher.h"
#include "util_aead.h"
#include "util_context.h"

static int bad_params(struct json_object *params, void **args,
		      struct smw_op_context **ctx,
		      struct smw_op_context **dest_ctx)
{
	int ret = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error;

	if (!params || !args || !ctx)
		return ret;

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case CTX_NULL:
	case SRC_CPY_CTX_NULL:
		*ctx = NULL;
		break;

	case DST_CPY_CTX_NULL:
		if (dest_ctx)
			*dest_ctx = NULL;
		else
			ret = ERR_CODE(BAD_ARGS);

		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

static int find_context_node(struct subtest_data *subtest,
			     struct json_object *obj, unsigned int index,
			     unsigned int *context_id,
			     struct smw_op_context **context)
{
	int status = ERR_CODE(BAD_PARAM_TYPE);

	struct json_object *array_member = NULL;
	int json_ctx_id = 0;

	array_member = json_object_array_get_idx(obj, index);

	if (json_object_get_type(array_member) != json_type_int) {
		DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
		goto end;
	}

	json_ctx_id = json_object_get_int(array_member);
	if (SET_OVERFLOW(json_ctx_id, *context_id))
		DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);

	status = ERR_CODE(PASSED);

	status = util_context_find_node(list_op_ctxs(subtest), *context_id,
					context);
	if (status != ERR_CODE(PASSED)) {
		DBG_PRINT("Failed to find context node");
		return status;
	}

end:
	return status;
}

static int copy_output_data_node(struct subtest_data *subtest,
				 unsigned int dst_ctx_id,
				 unsigned int src_ctx_id)
{
	int res = ERR_CODE(PASSED);

	bool copy_output = false;
	char *op_name = NULL;

	res = util_read_json_type(&copy_output, COPY_OUTPUT_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		if (!copy_output) {
			DBG_PRINT("Copy output data node ignored");
			return res;
		}

		res = util_read_json_type(&op_name, TYPE_OBJ, t_string,
					  subtest->params);
		if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
			DBG_PRINT_MISS_PARAM("Operation name");
			return ERR_CODE(MISSING_PARAMS);
		}

		if (!op_name) {
			DBG_PRINT_MISS_PARAM("Operation name");
			return ERR_CODE(MISSING_PARAMS);
		}

		/*
		 * Copy the output data node to the respective output data list based on
		 * operation type.
		 */
		if (!strcmp(op_name, OP_AEAD_MULTI_PART))
			res = util_aead_copy_node(list_aeads(subtest),
						  dst_ctx_id, src_ctx_id);
		else if (!strcmp(op_name, OP_CIPHER_MULTI_PART))
			res = util_cipher_copy_node(list_ciphers(subtest),
						    dst_ctx_id, src_ctx_id);

	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		res = ERR_CODE(PASSED);
	}

	return res;
}

int allocate_context(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	struct smw_context_args args = { 0 };
	struct smw_context_args *args_ptr = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	res = bad_params(subtest->params, (void **)&args_ptr, &args.context,
			 NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	subtest->smw_status = smw_allocate_context(args_ptr);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		return res;
	}

	/*
	 * Add context in linked list if context allocation succeeds and test isn't
	 * an API test
	 */
	if (ctx_id != UINT_MAX)
		res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
					    args.context);

	return res;
}

int cancel_operation(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	struct smw_context_args args = { 0 };
	struct smw_context_args *args_ptr = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	res = bad_params(subtest->params, (void **)&args_ptr, &args.context,
			 NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	subtest->smw_status = smw_cancel_operation(args_ptr);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		return res;
	}

	res = util_context_update_node(list_op_ctxs(subtest), ctx_id,
				       args.context);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Failed to update context node data");
		return res;
	}

	return res;
}

int copy_context(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_copy_context_args args = { 0 };
	struct smw_copy_context_args *args_ptr = &args;

	unsigned int dst_ctx_id = 0;
	unsigned int src_ctx_id = 0;
	struct json_object *obj = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	/* Context ID is a mandatory parameter except for API tests */
	res = util_read_json_type(&obj, CTX_ID_OBJ, t_buffer, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED))
		return res;

	if (obj) {
		/*
		 * Context ID must be an array of integer. First member
		 * represents the source ID, second the destination ID
		 */

		if (json_object_get_type(obj) != json_type_array) {
			DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		if (json_object_array_length(obj) != 2) {
			DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		/* Get source context ID and node data */
		res = find_context_node(subtest, obj, 0, &src_ctx_id,
					&args.src_context);
		if (res != ERR_CODE(PASSED))
			return res;

		/* Get destination context ID and node data */
		res = find_context_node(subtest, obj, 1, &dst_ctx_id,
					&args.dst_context);
		if (res != ERR_CODE(PASSED))
			return res;
	} else if (is_api_test(subtest)) {
		args.src_context = (struct smw_op_context *)INTPTR_MAX;
		args.dst_context = (struct smw_op_context *)INTPTR_MAX;
	}

	res = bad_params(subtest->params, (void **)&args_ptr, &args.src_context,
			 &args.dst_context);
	if (res != ERR_CODE(PASSED))
		goto exit;

	subtest->smw_status = smw_copy_context(args_ptr);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

	if (is_api_test(subtest))
		goto exit;

	if (res == ERR_CODE(PASSED))
		res = copy_output_data_node(subtest, dst_ctx_id, src_ctx_id);

exit:
	return res;
}
