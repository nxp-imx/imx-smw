// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2024 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "operation_context.h"

enum smw_status_code smw_cancel_operation(struct smw_op_context *context)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_cancel_op_args args = { .ctx = context };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct subsystem_func *subsystem_func = NULL;
	struct smw_crypto_context_ops *ops = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!context || !context->handle)
		goto end;

	if (SET_OVERFLOW((uintptr_t)context->reserved, subsystem_id))
		goto end;

	if (subsystem_id >= SUBSYSTEM_ID_NB)
		goto end;

	subsystem_func = smw_config_get_subsystem_func(subsystem_id);
	if (!subsystem_func || !subsystem_func->ctx_ops) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	ops = subsystem_func->ctx_ops();

	if (!ops || !ops->cancel) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	status = ops->cancel(&args);

	if (status == SMW_STATUS_OK) {
		context->handle = NULL;
		context->reserved = NULL;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_copy_context(struct smw_op_context *dst,
				      struct smw_op_context *src)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_copy_ctx_args args = { .src = src, .dst = dst };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct subsystem_func *subsystem_func = NULL;
	struct smw_crypto_context_ops *ops = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!src || !src->handle || !dst)
		goto end;

	if (SET_OVERFLOW((uintptr_t)src->reserved, subsystem_id))
		goto end;

	if (subsystem_id >= SUBSYSTEM_ID_NB)
		goto end;

	subsystem_func = smw_config_get_subsystem_func(subsystem_id);
	if (!subsystem_func || !subsystem_func->ctx_ops) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	ops = subsystem_func->ctx_ops();

	if (!ops || !ops->copy) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	status = ops->copy(&args);

	if (status == SMW_STATUS_OK)
		dst->reserved = src->reserved;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline void *
smw_crypto_get_cancel_handle(struct smw_crypto_cancel_op_args *args)
{
	if (args && args->ctx)
		return args->ctx->handle;

	return NULL;
}

inline void *
smw_crypto_get_copy_src_handle(struct smw_crypto_copy_ctx_args *args)
{
	if (args && args->src)
		return args->src->handle;

	return NULL;
}

inline void
smw_crypto_set_copy_dst_handle(struct smw_crypto_copy_ctx_args *args,
			       void *handle)
{
	if (args && args->dst)
		args->dst->handle = handle;
}
