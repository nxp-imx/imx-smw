// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_context.h"
#include "util_cipher.h"
#include "types.h"
#include "json_types.h"
#include "keymgr.h"
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
		if (*args)
			(*args)->handle = NULL;
		else
			ret = ERR_CODE(BAD_ARGS);
		break;

	case DST_CPY_ARGS_NULL:
		*dst = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int cancel_operation(json_object *params, struct cmn_params *cmn_params,
		     enum smw_status_code *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int ctx_id = 0;
	json_object *ctx_id_obj;
	struct smw_op_context args = { 0 };
	struct smw_op_context *args_ptr = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx,
					  .reserved = NULL };

	if (!params || !cmn_params || !ret_status) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Context ID is a mandatory parameter except for API tests */
	if (json_object_object_get_ex(params, CTX_ID_OBJ, &ctx_id_obj)) {
		ctx_id = json_object_get_int(ctx_id_obj);
	} else if (!is_api_test(cmn_params)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	if (!is_api_test(cmn_params)) {
		res = util_context_find_node(list_op_ctxs(cmn_params), ctx_id,
					     &args_ptr);
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
	if (CHECK_RESULT(*ret_status, cmn_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	return res;
}

int copy_context(json_object *params, struct cmn_params *cmn_params,
		 enum smw_status_code *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int dst_ctx_id = 0;
	int src_ctx_id = 0;
	int op_copy_ctx = 0;
	json_object *obj;
	json_object *array_member;
	struct smw_op_context *dst_args_ptr = NULL;
	struct smw_op_context *src_args_ptr = NULL;
	struct smw_op_context empty_ctx = { .handle = &empty_ctx,
					    .reserved = NULL };

	if (!params || !cmn_params || !ret_status) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Initialize the source context to be empty */
	src_args_ptr = &empty_ctx;

	/* Context ID is a mandatory parameter except for API tests */
	if (json_object_object_get_ex(params, CTX_ID_OBJ, &obj)) {
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

		array_member = json_object_array_get_idx(obj, 0);

		if (json_object_get_type(array_member) != json_type_int) {
			DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		src_ctx_id = json_object_get_int(array_member);

		res = util_context_find_node(list_op_ctxs(cmn_params),
					     src_ctx_id, &src_args_ptr);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to find context node");
			return res;
		}

		array_member = json_object_array_get_idx(obj, 1);

		if (json_object_get_type(array_member) != json_type_int) {
			DBG_PRINT_BAD_PARAM(CTX_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		dst_ctx_id = json_object_get_int(array_member);
	} else if (!is_api_test(cmn_params)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	dst_args_ptr = malloc(sizeof(struct smw_op_context));
	if (!dst_args_ptr)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	res = bad_params(params, &src_args_ptr, &dst_args_ptr);
	if (res != ERR_CODE(PASSED))
		goto exit_free;

	*ret_status = smw_copy_context(dst_args_ptr, src_args_ptr);
	if (CHECK_RESULT(*ret_status, cmn_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	if (is_api_test(cmn_params))
		goto exit_free;

	if (*ret_status == SMW_STATUS_OK && res == ERR_CODE(PASSED)) {
		res = util_context_add_node(list_op_ctxs(cmn_params),
					    dst_ctx_id, dst_args_ptr);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to add context node");
			goto exit_free;
		}

		res = util_read_json_type(&op_copy_ctx, COPY_CIPHER_CTX, t_int,
					  params);
		if (res == ERR_CODE(PASSED)) {
			if (op_copy_ctx != 1) {
				DBG_PRINT("Copy cipher context ignored");
				goto exit;
			}

			/* Copy cipher output data node */
			res = util_cipher_copy_node(list_ciphers(cmn_params),
						    dst_ctx_id, src_ctx_id);
		} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
			res = ERR_CODE(PASSED);
		}

		goto exit;
	}

exit_free:
	if (dst_args_ptr)
		free(dst_args_ptr);

exit:
	return res;
}
