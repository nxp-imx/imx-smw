/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023-2024 NXP
 */

#ifndef __OPERATION_CONTEXT_H__
#define __OPERATION_CONTEXT_H__

#include "smw_crypto.h"
#include "subsystems.h"

enum smw_crypto_op_id {
	SMW_CRYPTO_OP_ID_AEAD_MULTI_PART,
	SMW_CRYPTO_OP_ID_CIPHER_MULTI_PART,
	SMW_CRYPTO_OP_ID_HASH_MULTI_PART,
	SMW_CRYPTO_OP_ID_NB,
	SMW_CRYPTO_OP_ID_INVALID
};

enum ctx_op_state {
	CTX_OP_UNUSED,
	/* SMW op context is allocated but not initialized */
	CTX_OP_STATE_ALLOC,
	/* subsystem specific context is allocated and context is initialized */
	CTX_OP_STATE_INIT
};

/**
 * struct smw_op_context - Cryptographic operation context structure
 * @subsystem_id: Subsystem ID
 * @op_id: Operation ID
 * @op_state: Context operation state
 * @subsystem_context: Pointer to subsystem specific context
 *
 * @subsystem_context is allocated and managed in the subsystem wrapper.
 */
struct smw_op_context {
	enum subsystem_id subsystem_id;
	enum smw_crypto_op_id op_id;
	enum ctx_op_state op_state;
	void *subsystem_context;
};

/**
 * struct smw_crypto_context_ops - Internal context operations structure
 * @cancel: Pointer to cancel context function
 * @copy: Pointer to copy context function
 * @free: Pointer to free context function
 */
struct smw_crypto_context_ops {
	int (*cancel)(struct smw_op_context *ctx);
	int (*copy)(struct smw_op_context *src_ctx,
		    struct smw_op_context *dst_ctx);
	void (*free)(struct smw_op_context *ctx);
};

/**
 * smw_crypto_set_ctx_subsystem_id() - Set subsystem_id field in the op context
 * @op_context: Pointer to operation context arguments structure
 * @subsystem_id: Secure Subsystem ID
 *
 * Return:
 * none
 */
void smw_crypto_set_ctx_subsystem_id(struct smw_op_context *op_context,
				     enum subsystem_id subsystem_id);

/**
 * smw_crypto_copy_ctx_members() - Copy source ctx structure members to dest
 * @dst_context: Pointer to destination operation context arguments structure
 * @src_context: Pointer to source operation context arguments structure
 *
 * This functions copies the required members from the source operation context
 * arguments structure to destination operation context arguments structure.
 *
 * Return:
 * none
 */
void smw_crypto_copy_ctx_members(struct smw_op_context *dst_context,
				 struct smw_op_context *src_context);

/**
 * smw_utils_free_context() - Free resources allocated to operation context
 * @op_context: Pointer to operation context argument structure
 *
 * This function releases all the memory allocated to operation context based on
 * the internal context operation state.
 * If the context operation state is CTX_OP_STATE_ALLOC, memory allocated to SMW
 * operation context is released.
 * If the context operation state is CTX_OP_STATE_INIT, memory allocated to
 * subsytem specific context is released before releasing SMW operation context.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_INVALID_PARAM            - Invalid argument parameter
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Operation not supported
 */
int smw_utils_free_context(struct smw_op_context **op_context);

/**
 * smw_utils_cancel_operation() - Cancel multi-part operation and free resources
 * @op_context: Pointer to operation context argument structure
 *
 * This function cancels the on-going multi-part operation. Additionally, it
 * releases all the memory allocated to operation context based on the internal
 * context operation state.
 * If the context operation state is CTX_OP_STATE_ALLOC, memory allocated to SMW
 * operation context is released.
 * If the context operation state is CTX_OP_STATE_INIT, memory allocated to
 * subsytem specific context is released before releasing SMW operation context.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_INVALID_PARAM            - Invalid argument parameter
 * SMW_STATUS_OPERATION_NOT_SUPPORTED  - Operation not supported
 */
int smw_utils_cancel_operation(struct smw_op_context **op_context);

#endif /* __OPERATION_CONTEXT_H__ */
