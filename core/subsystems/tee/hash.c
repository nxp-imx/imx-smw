// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "hash.h"
#include "tee.h"
#include "smw_status.h"

/**
 * set_hash_context() - Allocate and initialize Hash subsystem specific ctx
 * @op_context: Pointer to operation context arguments structure
 * @context: Pointer to TEE shared context structure
 *
 * This function initializes the members of operation context structure. It also
 * allocates memory to Hash subsystem specific context and initializes it's
 * members.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE - Memory allocation failure
 */
static int set_hash_context(struct smw_op_context *op_context,
			    struct shared_context *context)
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

	hash_ctx->tee_handle = context->handle;

	op_context->subsystem_context = hash_ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_TEE);

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * hash() - Call TA hash operation.
 * @args: Hash arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int hash(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_hash_args *hash_args = args;
	enum tee_algorithm_id tee_algorithm_id = TEE_ALGORITHM_ID_INVALID;
	unsigned int output_length = 0;
	enum ta_commands cmd_id = CMD_HASH;
	struct smw_op_context *op_context = NULL;
	struct shared_context context = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!hash_args)
		goto exit;

	/*
	 * params[0] = Algorithm ID
	 * params[1] = Message
	 * params[2] = Digest
	 * params[3] = Shared context
	 */
	switch (hash_args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
		break;

	case SMW_OP_STEP_INIT:
		cmd_id = CMD_HASH_INIT;
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_MEMREF_TEMP_OUTPUT);
		break;

	case SMW_OP_STEP_UPDATE:
		cmd_id = CMD_HASH_UPDATE;
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_MEMREF_TEMP_INPUT);
		break;

	case SMW_OP_STEP_FINAL:
		cmd_id = CMD_HASH_FINAL;
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT);
		break;

	default:
		goto exit;
	}

	/* Convert smw algorithm ID to tee algorithm ID */
	if (hash_args->op_step == SMW_OP_STEP_ONESHOT ||
	    hash_args->op_step == SMW_OP_STEP_INIT) {
		status = tee_convert_hash_algorithm_id(hash_args->algo_id,
						       &tee_algorithm_id);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Algorithm ID not supported\n",
				       __func__);
			goto exit;
		}
	}

	op_context = smw_crypto_get_hash_op_context(hash_args);
	if ((hash_args->op_step == SMW_OP_STEP_UPDATE ||
	     hash_args->op_step == SMW_OP_STEP_FINAL)) {
		if (!op_context || !op_context->subsystem_context) {
			SMW_DBG_PRINTF(ERROR, "%s: Invalid Hash handle\n",
				       __func__);

			goto exit;
		}

		context.handle =
			((struct hash_context *)op_context->subsystem_context)
				->tee_handle;
	}

	op.params[0].value.a = tee_algorithm_id;
	op.params[1].tmpref.buffer = smw_crypto_get_hash_input_data(hash_args);
	op.params[1].tmpref.size = smw_crypto_get_hash_input_length(hash_args);
	op.params[2].tmpref.buffer = smw_crypto_get_hash_output_data(hash_args);

	/*
	 * For final operation, TEE requires an digest length set to 0 if digest
	 * buffer is NULL.
	 */
	if (!op.params[2].tmpref.buffer)
		op.params[2].tmpref.size = 0;
	else
		op.params[2].tmpref.size =
			smw_crypto_get_hash_output_length(hash_args);

	op.params[3].tmpref.buffer = &context;
	op.params[3].tmpref.size = sizeof(context);

	/* Invoke TA */
	status = execute_tee_cmd(cmd_id, &op);

	if ((hash_args->op_step == SMW_OP_STEP_ONESHOT ||
	     hash_args->op_step == SMW_OP_STEP_FINAL) &&
	    (status == SMW_STATUS_OK ||
	     status == SMW_STATUS_OUTPUT_TOO_SHORT)) {
		if (!SET_OVERFLOW(op.params[2].tmpref.size, output_length))
			smw_crypto_set_hash_output_length(hash_args,
							  output_length);
		else
			status = SMW_STATUS_OPERATION_FAILURE;
	}

	if (hash_args->op_step == SMW_OP_STEP_INIT && status == SMW_STATUS_OK)
		set_hash_context(op_context, &context);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_hash_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_HASH:
	case OPERATION_ID_HASH_MULTI_PART:
		*status = hash(args);
		break;
	default:
		return false;
	}

	return true;
}
