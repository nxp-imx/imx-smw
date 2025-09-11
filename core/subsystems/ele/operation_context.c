// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "utils.h"
#include "common.h"
#include "operation_context.h"

static int ele_cancel_operation(struct smw_op_context *ctx)
{
	(void)ctx;
	return SMW_STATUS_OK;
}

static void ele_free_context(struct smw_op_context *ctx)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx->subsystem_context)
		return;

	switch (ctx->op_id) {
	case SMW_CRYPTO_OP_ID_HASH_MULTI_PART:
		ele_free_hash_context(ctx);
		break;

	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		ele_free_sign_context(ctx);
		break;

	default:
		break;
	}

	SMW_UTILS_FREE(ctx->subsystem_context);
	ctx->subsystem_context = NULL;
}

static int ele_copy_context(struct smw_op_context *src_ctx,
			    struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (src_ctx->op_id) {
	case SMW_CRYPTO_OP_ID_HASH_MULTI_PART:
		status = ele_copy_hash_context(src_ctx, dst_ctx);
		break;

	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		status = ele_copy_sign_context(src_ctx, dst_ctx);
		break;

	default:
		break;
	}

	if (status == SMW_STATUS_OK)
		smw_crypto_copy_ctx_members(dst_ctx, src_ctx);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/* ELE context operations structure */
static struct smw_crypto_context_ops ele_ctx_ops = {
	.cancel = ele_cancel_operation,
	.copy = ele_copy_context,
	.free = ele_free_context
};

void *ele_get_ctx_ops(void)
{
	return &ele_ctx_ops;
}
