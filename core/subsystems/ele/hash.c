// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "hash.h"

#include "common.h"

/**
 * set_hash_context() - Initialize the operation context
 * @op_context: Pointer to operation context arguments structure
 * @op_args: Pointer to ELE Hash operation arguments
 * @digest_length: Digest length
 * This function initializes the members of operation context structure.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - One of the parameters is invalid
 */
static int set_hash_context(struct smw_op_context *op_context,
			    op_hash_one_go_args_t *op_args,
			    uint32_t digest_length)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct hash_context *hash_ctx = NULL;

	if (!op_context)
		goto end;

	op_context->op_id = SMW_CRYPTO_OP_ID_HASH_MULTI_PART;

	hash_ctx = SMW_UTILS_MALLOC(sizeof(*hash_ctx));
	if (!hash_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(DEBUG,
			       "Hash subsystem context allocation failure\n");
		goto end;
	}

	hash_ctx->ele_ctx = op_args->ctx;
	hash_ctx->ele_ctx_size = op_args->ctx_size;
	hash_ctx->ele_algo = op_args->algo;
	hash_ctx->digest_length = digest_length;

	op_context->subsystem_context = hash_ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash(struct hdl *hdl, op_hash_one_go_args_t *op_args)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_hash()\n"
		       "op_args_t\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%02X\n"
		       "    Input\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Output\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Context\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args->algo, op_args->svc_flags,
		       op_args->input, op_args->input_size, op_args->output,
		       op_args->output_size, op_args->ctx, op_args->ctx_size);

	err = hsm_do_hash(hdl->session, op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_do_hash returned %d\n", err);

	return ele_convert_err(err);
}

static int hash_one_shot(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	op_hash_one_go_args_t op_args = { 0 };
	struct smw_crypto_hash_args *hash_args = args;
	const struct ele_hash_algo *hash_algo = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_algo = ele_get_hash_algo(hash_args->algo_id);
	if (!hash_algo)
		goto end;

	op_args.input = smw_crypto_get_hash_input_data(hash_args);
	op_args.output = smw_crypto_get_hash_output_data(hash_args);
	op_args.input_size = smw_crypto_get_hash_input_length(hash_args);
	op_args.output_size = smw_crypto_get_hash_output_length(hash_args);
	op_args.algo = hash_algo->ele_algo;
	op_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;

	/* Get output length feature */
	if (!op_args.output) {
		smw_crypto_set_hash_output_length(hash_args, hash_algo->length);
		status = SMW_STATUS_OK;
		goto end;
	}

	status = hash(hdl, &op_args);

	/* Update digest size */
	smw_crypto_set_hash_output_length(hash_args, op_args.exp_output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_init(struct hdl *hdl, struct smw_crypto_hash_args *hash_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	op_hash_one_go_args_t op_args = { 0 };
	const struct ele_hash_algo *hash_algo = NULL;
	struct smw_op_context *op_context = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_crypto_get_hash_op_context(hash_args);
	if (!op_context)
		goto end;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_ELE);

	hash_algo = ele_get_hash_algo(hash_args->algo_id);
	if (!hash_algo)
		goto end;

	op_args.algo = hash_algo->ele_algo;
	op_args.svc_flags = HSM_HASH_FLAG_GET_CONTEXT;

	status = hash(hdl, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.ctx = SMW_UTILS_MALLOC(op_args.context_size);
	if (!op_args.ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(DEBUG, "ELE Hash context allocation failure\n");
		goto end;
	}

	op_args.input = smw_crypto_get_hash_input_data(hash_args),
	op_args.input_size = smw_crypto_get_hash_input_length(hash_args),
	op_args.svc_flags = HSM_HASH_FLAG_INIT;
	op_args.ctx_size = op_args.context_size;

	status = hash(hdl, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_hash_context(op_context, &op_args, hash_algo->length);

end:
	if (status != SMW_STATUS_OK && op_args.ctx)
		SMW_UTILS_FREE(op_args.ctx);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_update(struct hdl *hdl, struct smw_crypto_hash_args *hash_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	op_hash_one_go_args_t op_args = { 0 };
	struct hash_context *hash_ctx = NULL;
	struct smw_op_context *op_context = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_crypto_get_hash_op_context(hash_args);
	if (!op_context || !op_context->subsystem_context)
		goto end;

	hash_ctx = op_context->subsystem_context;

	op_args.ctx = hash_ctx->ele_ctx;
	op_args.input = smw_crypto_get_hash_input_data(hash_args);
	op_args.output = smw_crypto_get_hash_output_data(hash_args);
	op_args.input_size = smw_crypto_get_hash_input_length(hash_args);
	op_args.output_size = smw_crypto_get_hash_output_length(hash_args);
	op_args.algo = hash_ctx->ele_algo;
	op_args.svc_flags = HSM_HASH_FLAG_UPDATE;
	op_args.ctx_size = hash_ctx->ele_ctx_size;

	status = hash(hdl, &op_args);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_final(struct hdl *hdl, struct smw_crypto_hash_args *hash_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	op_hash_one_go_args_t op_args = { 0 };
	struct hash_context *hash_ctx = NULL;
	struct smw_op_context *op_context = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_crypto_get_hash_op_context(hash_args);
	if (!op_context || !op_context->subsystem_context)
		goto end;

	hash_ctx = op_context->subsystem_context;

	op_args.ctx = hash_ctx->ele_ctx;
	op_args.input = smw_crypto_get_hash_input_data(hash_args);
	op_args.output = smw_crypto_get_hash_output_data(hash_args);
	op_args.input_size = smw_crypto_get_hash_input_length(hash_args);
	op_args.output_size = smw_crypto_get_hash_output_length(hash_args);
	op_args.algo = hash_ctx->ele_algo;
	op_args.svc_flags = HSM_HASH_FLAG_FINAL;
	op_args.ctx_size = hash_ctx->ele_ctx_size;

	/* Get output length feature */
	if (!op_args.output) {
		smw_crypto_set_hash_output_length(hash_args,
						  hash_ctx->digest_length);
		status = SMW_STATUS_OK;
		goto end;
	}

	status = hash(hdl, &op_args);

	/* Update digest size */
	smw_crypto_set_hash_output_length(hash_args, op_args.exp_output_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int hash_multi_part(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_crypto_hash_args *hash_args = args;

	switch (hash_args->op_step) {
	case SMW_OP_STEP_INIT:
		status = hash_init(hdl, hash_args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = hash_update(hdl, hash_args);
		break;

	case SMW_OP_STEP_FINAL:
		status = hash_final(hdl, hash_args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_hash_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_HASH:
		*status = hash_one_shot(hdl, args);
		break;
	case OPERATION_ID_HASH_MULTI_PART:
		*status = hash_multi_part(hdl, args);
		break;
	default:
		return false;
	}

	return true;
}
