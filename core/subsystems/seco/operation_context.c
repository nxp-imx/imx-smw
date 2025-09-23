// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "compiler.h"

#include "utils.h"
#include "operation_context.h"

#include "keymgr_derive_tls12.h"

static int seco_cancel_operation(struct smw_op_context *ctx)
{
	(void)ctx;
	return SMW_STATUS_OK;
}

static int seco_copy_context(struct smw_op_context *src_ctx,
			     struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	switch (src_ctx->op_id) {
	case SMW_CRYPTO_OP_ID_HASH_MULTI_PART:
		status = seco_copy_hash_context(src_ctx, dst_ctx);
		break;

	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		status = seco_copy_sign_context(src_ctx, dst_ctx);
		break;

	default:
		break;
	}

	if (status == SMW_STATUS_OK)
		smw_crypto_copy_ctx_members(dst_ctx, src_ctx);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void seco_free_context(struct smw_op_context *ctx)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx->subsystem_context)
		return;

	switch (ctx->op_id) {
	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		seco_free_sign_context(ctx);
		break;

	case SMW_CRYPTO_OP_ID_TLS12:
		seco_free_tls12_context(ctx);

		break;

	default:
		break;
	}

	SMW_UTILS_FREE(ctx->subsystem_context);
	ctx->subsystem_context = NULL;
}

/* ELE context operations structure */
static struct smw_crypto_context_ops seco_ctx_ops = {
	.cancel = seco_cancel_operation,
	.copy = seco_copy_context,
	.free = seco_free_context
};

void *seco_get_ctx_ops(void)
{
	return &seco_ctx_ops;
}

__weak int seco_copy_hash_context(struct smw_op_context *src_ctx,
				  struct smw_op_context *dst_ctx)
{
	(void)src_ctx;
	(void)dst_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak void seco_free_sign_context(struct smw_op_context *ctx)
{
	(void)ctx;
}

__weak int seco_copy_sign_context(struct smw_op_context *src_ctx,
				  struct smw_op_context *dst_ctx)
{
	(void)src_ctx;
	(void)dst_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak void seco_free_tls12_context(struct smw_op_context *ctx)
{
	(void)ctx;
}
