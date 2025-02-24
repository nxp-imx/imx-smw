// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "utils.h"
#include "operation_context.h"

#include "keymgr_derive_tls12.h"

static int cancel_operation(struct smw_op_context *ctx)
{
	(void)ctx;
	return SMW_STATUS_OK;
}

static int copy_context(struct smw_op_context *src_ctx,
			struct smw_op_context *dst_ctx)
{
	(void)src_ctx;
	(void)dst_ctx;
	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static void free_context(struct smw_op_context *ctx)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx->subsystem_context)
		return;

	if (ctx->op_id == SMW_CRYPTO_OP_ID_TLS12 &&
	    ctx->op_state == CTX_OP_STATE_INIT) {
		struct seco_tls12_partial_data *partial =
			(struct seco_tls12_partial_data *)ctx->subsystem_context;

		if (partial->session_hash)
			SMW_UTILS_FREE(partial->session_hash);

		if (partial->peer_public_buffer)
			SMW_UTILS_FREE(partial->peer_public_buffer);

		if (partial->self_public_buffer)
			SMW_UTILS_FREE(partial->self_public_buffer);
	}

	SMW_UTILS_FREE(ctx->subsystem_context);
	ctx->subsystem_context = NULL;
}

/* ELE context operations structure */
static struct smw_crypto_context_ops seco_ctx_ops = { .cancel =
							      cancel_operation,
						      .copy = copy_context,
						      .free = free_context };

void *seco_get_ctx_ops(void)
{
	return &seco_ctx_ops;
}
