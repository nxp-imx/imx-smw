// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "config.h"
#include "tee.h"

#include "smw_status.h"

static int get_subsystem_context_handle(struct smw_op_context *ctx,
					void **handle)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct aead_context *aead_ctx = NULL;
	struct cipher_context *cipher_ctx = NULL;
	struct hash_context *hash_ctx = NULL;
	struct sign_context *sign_ctx = NULL;

	if (!ctx->subsystem_context)
		goto end;

	switch (ctx->op_id) {
	case SMW_CRYPTO_OP_ID_AEAD_MULTI_PART:
		aead_ctx = ctx->subsystem_context;
		*handle = aead_ctx->tee_handle;

		status = SMW_STATUS_OK;
		break;

	case SMW_CRYPTO_OP_ID_CIPHER_MULTI_PART:
		cipher_ctx = ctx->subsystem_context;
		*handle = cipher_ctx->tee_handle;

		status = SMW_STATUS_OK;
		break;

	case SMW_CRYPTO_OP_ID_HASH_MULTI_PART:
		hash_ctx = ctx->subsystem_context;
		*handle = hash_ctx->tee_handle;

		status = SMW_STATUS_OK;
		break;

	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		sign_ctx = ctx->subsystem_context;
		hash_ctx = sign_ctx->hash_ctx.subsystem_context;
		if (!hash_ctx)
			break;

		*handle = hash_ctx->tee_handle;

		status = SMW_STATUS_OK;
		break;

	default:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;
	}

end:
	SMW_DBG_PRINTF(EXTRA, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * free_context() - Free all the memory allocated to operation context
 * @ctx: Pointer to SMW operation context arguments structure
 *
 * Return:
 * None.
 */
static void tee_free_context(struct smw_op_context *ctx)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ctx->subsystem_context)
		return;

	switch (ctx->op_id) {
	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		tee_free_sign_context(ctx);
		break;

	default:
		break;
	}

	SMW_UTILS_FREE(ctx->subsystem_context);
	ctx->subsystem_context = NULL;
}

/**
 * cancel_operation() - Call TA cancel operation
 * @ctx: Pointer to SMW operation context arguments structure
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 * SMW_STATUS_SUBSYSTEM_FAILURE       - Subsystem failure
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Operation not supported by subsystem
 */
static int tee_cancel_operation(struct smw_op_context *ctx)
{
	int status = SMW_STATUS_OK;

	struct shared_context shared_ctx = { 0 };
	TEEC_Operation op = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_subsystem_context_handle(ctx, &shared_ctx.handle);
	if (status != SMW_STATUS_OK || !shared_ctx.handle)
		goto end;

	/*
	 * params[0] = Operation handle
	 * params[1] = None
	 * params[2] = None
	 * params[3] = None
	 */

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = &shared_ctx;
	op.params[0].tmpref.size = sizeof(shared_ctx);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_CANCEL_OP, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * allocate_copy_subsystem_context() - Allocate and copy destination op context
 * @src_context: Pointer to source operation context arguments structure
 * @dst_context: Pointer to destination operation context arguments structure
 * @tee_dst_ctx: Pointer to optee context operation handle structure
 *
 * This function allocates memory to subsystem specific destination operation
 * context structure and also initializes it's members.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE           - Memory allocation failure
 * SMw_STATUS_OPERATION_NOT_SUPPORTED - Operation is not supported
 */
static int allocate_copy_subsystem_context(struct smw_op_context *src_context,
					   struct smw_op_context *dst_context,
					   struct shared_context *tee_dst_ctx)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct aead_context *src_aead_ctx = NULL;
	struct aead_context *dst_aead_ctx = NULL;
	struct cipher_context *dst_cipher_ctx = NULL;
	struct hash_context *dst_hash_ctx = NULL;

	switch (src_context->op_id) {
	case SMW_CRYPTO_OP_ID_AEAD_MULTI_PART:
		src_aead_ctx = src_context->subsystem_context;

		dst_aead_ctx = SMW_UTILS_MALLOC(sizeof(*dst_aead_ctx));
		if (!dst_aead_ctx) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		dst_aead_ctx->iv_len = src_aead_ctx->iv_len;
		if (dst_aead_ctx->iv_len)
			SMW_UTILS_MEMCPY(dst_aead_ctx->iv, src_aead_ctx->iv,
					 src_aead_ctx->iv_len);

		dst_aead_ctx->tee_handle = tee_dst_ctx->handle;
		dst_context->subsystem_context = dst_aead_ctx;

		status = SMW_STATUS_OK;
		break;

	case SMW_CRYPTO_OP_ID_CIPHER_MULTI_PART:
		dst_cipher_ctx = SMW_UTILS_MALLOC(sizeof(*dst_cipher_ctx));
		if (!dst_cipher_ctx) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		dst_cipher_ctx->tee_handle = tee_dst_ctx->handle;
		dst_context->subsystem_context = dst_cipher_ctx;

		status = SMW_STATUS_OK;
		break;

	case SMW_CRYPTO_OP_ID_HASH_MULTI_PART:
		dst_hash_ctx = SMW_UTILS_MALLOC(sizeof(*dst_hash_ctx));
		if (!dst_hash_ctx) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		dst_hash_ctx->tee_handle = tee_dst_ctx->handle;
		dst_context->subsystem_context = dst_hash_ctx;

		status = SMW_STATUS_OK;
		break;

	case SMW_CRYPTO_OP_ID_SIGN_MULTI_PART:
		status = tee_copy_sign_context(src_context, dst_context,
					       tee_dst_ctx);
		break;

	default:
		goto end;
	}

	smw_crypto_copy_ctx_members(dst_context, src_context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * copy_context() - Call TA copy context operation
 * @src_ctx: Pointer to source operation context arguments structure
 * @dst_ctx: Pointer to destination operation context arguments structure
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 * SMW_STATUS_SUBSYSTEM_FAILURE       - Subsystem failure
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Operation not supported by subsystem
 */
static int tee_copy_context(struct smw_op_context *src_ctx,
			    struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_OK;

	struct shared_context src_shared_ctx = { 0 };
	struct shared_context dst_shared_ctx = { 0 };
	TEEC_Operation op = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_subsystem_context_handle(src_ctx, &src_shared_ctx.handle);
	if (status != SMW_STATUS_OK || !src_shared_ctx.handle)
		goto end;

	/*
	 * params[0] = Source operation handle
	 * params[1] = Destination operation handle
	 * params[2] = None
	 * params[3] = None
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INOUT,
				 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = &src_shared_ctx;
	op.params[0].tmpref.size = sizeof(src_shared_ctx);
	op.params[1].tmpref.buffer = &dst_shared_ctx;
	op.params[1].tmpref.size = sizeof(dst_shared_ctx);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_COPY_CTX, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status == SMW_STATUS_OK)
		status = allocate_copy_subsystem_context(src_ctx, dst_ctx,
							 &dst_shared_ctx);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/* TEE context operations structure */
static struct smw_crypto_context_ops tee_ctx_ops = {
	.cancel = tee_cancel_operation,
	.copy = tee_copy_context,
	.free = tee_free_context
};

void *tee_get_ctx_ops(void)
{
	return &tee_ctx_ops;
}
