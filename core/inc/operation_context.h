/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __OPERATION_CONTEXT_H__
#define __OPERATION_CONTEXT_H__

#include "smw_crypto.h"

/**
 * struct smw_crypto_cancel_op_args - Internal cancel operation structure
 * @ctx: Pointer to operation context
 */
struct smw_crypto_cancel_op_args {
	struct smw_op_context *ctx;
};

/**
 * struct smw_crypto_copy_ctx_args - Internal copy context structure
 * @src: Pointer to source operation context
 * @dst: Pointer to destination operation context
 */
struct smw_crypto_copy_ctx_args {
	struct smw_op_context *src;
	struct smw_op_context *dst;
};

/**
 * struct smw_crypto_context_ops - Internal context operations structure
 * @subsystem: SMW subsystem ID
 * @cancel: Pointer to cancel context function
 * @copy: Pointer to copy context function
 */
struct smw_crypto_context_ops {
	enum subsystem_id subsystem;
	int (*cancel)(struct smw_crypto_cancel_op_args *args);
	int (*copy)(struct smw_crypto_copy_ctx_args *args);
};

/**
 * smw_crypto_get_cancel_handle() - Get cancel operation handle argument
 * @args: Pointer to internal cancel operation structure
 *
 * Return:
 * Pointer to handle
 * NULL
 */
void *smw_crypto_get_cancel_handle(struct smw_crypto_cancel_op_args *args);

/**
 * smw_crypto_get_copy_src_handle() - Get source copy context operation handle
 * @args: Pointer to internal copy context structure
 *
 * Return:
 * Pointer to handle
 * NULL
 */
void *smw_crypto_get_copy_src_handle(struct smw_crypto_copy_ctx_args *args);

/**
 * smw_crypto_set_copy_dst_handle() - Set destination copy context operation
 *                                    handle
 * @args: Pointer to internal copy context structure
 *
 * Return:
 * none
 */
void smw_crypto_set_copy_dst_handle(struct smw_crypto_copy_ctx_args *args,
				    void *handle);

#endif /* __OPERATION_CONTEXT_H__ */
