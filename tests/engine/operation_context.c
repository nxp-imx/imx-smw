// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_context.h"
#include "types.h"
#include "json_types.h"
#include "keymgr.h"
#include "cipher.h"
#include "operation_context.h"

#include "smw_crypto.h"
#include "smw_status.h"

static int bad_params(json_object *params, struct smw_op_context **args,
		      struct smw_op_context **dst)
{
	int ret;
	enum arguments_test_err_case error;

	if (!params || !args)
		return ERR_CODE(BAD_ARGS);

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case CTX_HANDLE_NULL:
		(*args)->handle = NULL;
		break;

	case DST_CPY_ARGS_NULL:
		*dst = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int cancel_operation(json_object *params,
		     struct common_parameters *common_params,
		     struct context_list *ctx, int *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int ctx_id;
	json_object *ctx_id_obj;
	struct smw_op_context args = { 0 };
	struct smw_op_context *args_ptr = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx,
					  .reserved = NULL };

	if (!params || !common_params || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	/* Context ID is a mandatory parameter except for API tests */
	if (json_object_object_get_ex(params, CTX_ID_OBJ, &ctx_id_obj)) {
		ctx_id = json_object_get_int(ctx_id_obj);
	} else if (!common_params->is_api_test) {
		DBG_PRINT_MISS_PARAM(__func__, "Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	if (!common_params->is_api_test) {
		res = util_context_find_node(ctx, ctx_id, &args_ptr);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to find context node");
			return res;
		}
	} else {
		args_ptr = &api_ctx;
	}

	res = bad_params(params, &args_ptr, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	*ret_status = smw_cancel_operation(args_ptr);
	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	return res;
}

int copy_context(json_object *params, struct common_parameters *common_params,
		 struct context_list **ctx, int *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int dst_ctx_id = 0;
	int src_ctx_id = 0;
	json_object *obj;
	json_object *array_member;
	struct smw_op_context *dst_args_ptr = NULL;
	struct smw_op_context *src_args_ptr = NULL;
	struct smw_op_context api_ctx = { .handle = &api_ctx,
					  .reserved = NULL };

	if (!params || !common_params || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	/* Context ID is a mandatory parameter except for API tests */
	if (json_object_object_get_ex(params, CTX_ID_OBJ, &obj)) {
		/*
		 * Context ID must be an array of integer. First member
		 * represents the source ID, second the destination ID
		 */

		if (json_object_get_type(obj) != json_type_array) {
			DBG_PRINT_BAD_PARAM(__func__, CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		if (json_object_array_length(obj) != 2) {
			DBG_PRINT_BAD_PARAM(__func__, CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		array_member = json_object_array_get_idx(obj, 0);

		if (json_object_get_type(array_member) != json_type_int) {
			DBG_PRINT_BAD_PARAM(__func__, CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		src_ctx_id = json_object_get_int(array_member);

		res = util_context_find_node(*ctx, src_ctx_id, &src_args_ptr);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to find context node");
			return res;
		}

		array_member = json_object_array_get_idx(obj, 1);

		if (json_object_get_type(array_member) != json_type_int) {
			DBG_PRINT_BAD_PARAM(__func__, CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		dst_ctx_id = json_object_get_int(array_member);
	} else if (!common_params->is_api_test) {
		DBG_PRINT_MISS_PARAM(__func__, "Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	if (common_params->is_api_test) {
		src_args_ptr = &api_ctx;
		dst_args_ptr = &api_ctx;
	} else {
		dst_args_ptr = malloc(sizeof(struct smw_op_context));
		if (!dst_args_ptr)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	res = bad_params(params, &src_args_ptr, &dst_args_ptr);
	if (res != ERR_CODE(PASSED)) {
		if (!common_params->is_api_test)
			goto free;

		return res;
	}

	*ret_status = smw_copy_context(dst_args_ptr, src_args_ptr);
	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	if (*ret_status == SMW_STATUS_OK && res == ERR_CODE(PASSED) &&
	    !common_params->is_api_test) {
		res = util_context_add_node(ctx, dst_ctx_id, dst_args_ptr);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to add context node");
			goto free;
		}

		if (json_object_object_get_ex(params, COPY_CIPHER_CTX, &obj)) {
			if (json_object_get_type(obj) != json_type_int) {
				DBG_PRINT_BAD_PARAM(__func__, COPY_CIPHER_CTX);
				return ERR_CODE(BAD_PARAM_TYPE);
			}

			if (json_object_get_int(obj) != 1) {
				DBG_PRINT("Copy cipher context ignored");
				return ERR_CODE(PASSED);
			}

			/* Copy cipher output data node */
			res = cipher_copy_node(dst_ctx_id, src_ctx_id);
		}
	} else if (!common_params->is_api_test) {
		goto free;
	}

	return res;

free:
	if (dst_args_ptr)
		free(dst_args_ptr);

	return res;
}
