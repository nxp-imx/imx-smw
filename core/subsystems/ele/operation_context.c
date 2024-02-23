// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "operation_context.h"

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

static void free_context(struct smw_op_context **args)
{
	(void)args;
}

/* ELE context operations structure */
static struct smw_crypto_context_ops ele_ctx_ops = { .cancel = cancel_operation,
						     .copy = copy_context,
						     .free = free_context };

void *ele_get_ctx_ops(void)
{
	return &ele_ctx_ops;
}
