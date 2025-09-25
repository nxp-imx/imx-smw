// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "config.h"
#include "operation_context.h"

inline void smw_crypto_set_ctx_subsystem_id(struct smw_op_context *op_context,
					    enum subsystem_id subsystem_id)
{
	if (op_context)
		op_context->subsystem_id = subsystem_id;
}

inline int smw_crypto_get_ctx_subsystem_id(struct smw_op_context *op_context,
					   enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME;

	if (op_context) {
		if (op_context->subsystem_id < SUBSYSTEM_ID_NB)
			*subsystem_id = op_context->subsystem_id;

		status = SMW_STATUS_OK;
	}

	return status;
}

void smw_crypto_copy_ctx_members(struct smw_op_context *dst_context,
				 struct smw_op_context *src_context)
{
	dst_context->op_state = src_context->op_state;
	dst_context->subsystem_id = src_context->subsystem_id;
	dst_context->op_id = src_context->op_id;
}

enum smw_status_code smw_allocate_context(struct smw_context_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_API_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	args->context = SMW_UTILS_CALLOC(1, sizeof(*args->context));
	if (!args->context) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &args->context->subsystem_id);
	if (status != SMW_STATUS_OK) {
		SMW_UTILS_FREE(args->context);
		args->context = NULL;
		goto end;
	}

	status = SMW_STATUS_OK;
	args->context->op_state = CTX_OP_STATE_ALLOC;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_cancel_operation(struct smw_context_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_utils_cancel_operation(&args->context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_copy_context(struct smw_copy_context_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct subsystem_func *subsystem_func = NULL;
	struct smw_crypto_context_ops *ops = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->src_context || !args->dst_context)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	subsystem_func =
		smw_config_get_subsystem_func(args->src_context->subsystem_id);
	if (!subsystem_func || !subsystem_func->ctx_ops) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	ops = subsystem_func->ctx_ops();
	if (!ops) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	status = ops->copy(args->src_context, args->dst_context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
