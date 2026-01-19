// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2026 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "cipher.h"
#include "tee.h"

#include "smw_status.h"

#define TEE_CIPHER_ALGO_ID(_key_type, _smw_cipher_mode, _tee_cipher_mode)      \
	{                                                                      \
		.key_type = SMW_CONFIG_KEY_TYPE_ID_##_key_type,                \
		.cipher_mode = SMW_CONFIG_CIPHER_MODE_ID_##_smw_cipher_mode,   \
		.tee_algo = TEE_ALG_##_key_type##_##_tee_cipher_mode           \
	}

static const struct {
	enum smw_config_key_type_id key_type;
	enum smw_config_cipher_mode_id cipher_mode;
	uint32_t tee_algo;
} tee_cipher_algo_id[] = { TEE_CIPHER_ALGO_ID(AES, CBC, CBC_NOPAD),
			   TEE_CIPHER_ALGO_ID(AES, CTR, CTR),
			   TEE_CIPHER_ALGO_ID(AES, CTS, CTS),
			   TEE_CIPHER_ALGO_ID(AES, ECB, ECB_NOPAD),
			   TEE_CIPHER_ALGO_ID(AES, XTS, XTS),
			   TEE_CIPHER_ALGO_ID(DES, CBC, CBC_NOPAD),
			   TEE_CIPHER_ALGO_ID(DES, ECB, ECB_NOPAD),
			   TEE_CIPHER_ALGO_ID(DES3, CBC, CBC_NOPAD),
			   TEE_CIPHER_ALGO_ID(DES3, ECB, ECB_NOPAD),
			   TEE_CIPHER_ALGO_ID(SM4, ECB, ECB_NOPAD),
			   TEE_CIPHER_ALGO_ID(SM4, CBC, CBC_NOPAD),
			   TEE_CIPHER_ALGO_ID(SM4, CTR, CTR) };

static int get_tee_cipher_algo_id(enum smw_config_key_type_id key_type,
				  enum smw_config_cipher_mode_id cipher_mode,
				  uint32_t *tee_algo)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(tee_cipher_algo_id); i++) {
		if (key_type == tee_cipher_algo_id[i].key_type &&
		    cipher_mode == tee_cipher_algo_id[i].cipher_mode) {
			*tee_algo = tee_cipher_algo_id[i].tee_algo;
			return SMW_STATUS_OK;
		}
	}

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

/**
 * set_cipher_context() - Allocate and initialize cipher subsystem specific ctx
 * @op_context: Pointer to operation context arguments structure
 * @handle: Pointer to TEE context operation handle structure
 *
 * This function initializes the members of operation context structure. It also
 * allocates memory to cipher subsystem specific context and initializes it's
 * members.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE - Memory allocation failure
 */
static int set_cipher_context(struct smw_op_context *op_context, void *handle)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct cipher_context *cipher_ctx = NULL;

	if (!op_context)
		goto end;

	op_context->op_id = SMW_CRYPTO_OP_ID_CIPHER_MULTI_PART;

	cipher_ctx = SMW_UTILS_MALLOC(sizeof(*cipher_ctx));
	if (!cipher_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(DEBUG,
			       "Cipher subsystem context allocation failure\n");
		goto end;
	}

	cipher_ctx->tee_handle = handle;

	op_context->subsystem_context = cipher_ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
get_tee_cipher_operation_and_usage(enum smw_config_cipher_op_type_id smw_op,
				   uint32_t *tee_op, unsigned int *key_usage)
{
	switch (smw_op) {
	case SMW_CONFIG_CIPHER_OP_TYPE_ID_ENCRYPT:
		*tee_op = TEE_MODE_ENCRYPT;
		*key_usage = TEE_KEY_USAGE_ENCRYPT;
		break;

	case SMW_CONFIG_CIPHER_OP_TYPE_ID_DECRYPT:
		*tee_op = TEE_MODE_DECRYPT;
		*key_usage = TEE_KEY_USAGE_DECRYPT;
		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

static int cipher_init(struct smw_op_context *op_context,
		       struct smw_crypto_cipher_args *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	int res = SMW_STATUS_OK;
	unsigned int key_idx = 0;
	unsigned int key_id = INVALID_KEY_ID;
	uint32_t param2_type = TEEC_NONE;
	enum smw_config_key_type_id key_type = 0;
	struct shared_context context = { 0 };
	unsigned int key_usage = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->nb_keys > 2)
		goto end;

	/* Get 1st key type as reference */
	key_type = args->keys_desc[0]->identifier.type_id;

	/*
	 * params[0] = TEE Algo ID, TEE Operation
	 * params[1] = Key ids as integer or as integer array
	 * params[2] = IV or none
	 * params[3] = Operation handle
	 */

	/* Get OPTEE algorithm */
	status = get_tee_cipher_algo_id(key_type, args->mode_id,
					&op.params[0].value.a);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get OPTEE operation and key usage */
	status = get_tee_cipher_operation_and_usage(args->op_type_id,
						    &op.params[0].value.b,
						    &key_usage);
	if (status != SMW_STATUS_OK)
		goto end;

	for (; key_idx < args->nb_keys; key_idx++) {
		key_id = smw_crypto_get_cipher_key_id(args, key_idx);

		/*
		 * If the key id is not valid, import the key first in
		 * TEE, then imported key is removed before leaving.
		 */
		if (key_id == INVALID_KEY_ID) {
			/* If some keys are defined as buffer import them */
			status = tee_import_key_buffer(args->keys_desc[key_idx],
						       &key_id, key_usage);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		/*
		 * Only 2 keys maximum can be handled in the TEE TA Cipher
		 * operation.
		 * The op.params[1].value (a or b) are re-used to delete
		 * imported key. As this TA operation parameter is an
		 * input, it can't be overwritten.
		 */
		if (key_idx)
			op.params[1].value.b = key_id;
		else
			op.params[1].value.a = key_id;
	}

	if (smw_crypto_get_cipher_iv(args)) {
		op.params[2].tmpref.buffer = smw_crypto_get_cipher_iv(args);
		op.params[2].tmpref.size = smw_crypto_get_cipher_iv_len(args);
		param2_type = TEEC_MEMREF_TEMP_INPUT;
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 param2_type, TEEC_MEMREF_TEMP_INOUT);

	context.one_shot =
		(args->op_step == SMW_OP_STEP_ONESHOT) ? true : false;

	op.params[3].tmpref.buffer = &context;
	op.params[3].tmpref.size = sizeof(context);

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_TEE);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_CIPHER_INIT, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status == SMW_STATUS_OK)
		status = set_cipher_context(op_context, context.handle);

	/* Delete imported ephemeral keys */
	for (key_idx = 0; key_idx < args->nb_keys; key_idx++) {
		key_id = smw_crypto_get_cipher_key_id(args, key_idx);
		if (key_id == INVALID_KEY_ID) {
			/*
			 * The op.params[1].value (a or b) are re-used to get
			 * imported key id.
			 */
			if (key_idx)
				key_id = op.params[1].value.b;
			else
				key_id = op.params[1].value.a;

			res = tee_delete_key(key_id);
			status = (status == SMW_STATUS_OK) ? res : status;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part_common(struct smw_op_context *op_context,
				    struct smw_crypto_cipher_args *args,
				    enum ta_commands ta_cmd)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	struct shared_context context = { 0 };
	struct cipher_context *cipher_ctx = NULL;

	unsigned int output_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op_context)
		goto end;

	cipher_ctx = op_context->subsystem_context;
	if (!cipher_ctx)
		goto end;

	context.handle = cipher_ctx->tee_handle;
	context.one_shot =
		(args->op_step == SMW_OP_STEP_ONESHOT) ? true : false;

	/*
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = None
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	op.params[0].tmpref.buffer = &context;
	op.params[0].tmpref.size = sizeof(context);
	op.params[1].tmpref.buffer = smw_crypto_get_cipher_input(args);
	op.params[1].tmpref.size = smw_crypto_get_cipher_input_len(args);
	op.params[2].tmpref.buffer = smw_crypto_get_cipher_output(args);
	op.params[2].tmpref.size = smw_crypto_get_cipher_output_len(args);

	/* Invoke TA */
	status = execute_tee_cmd(ta_cmd, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Cipher %s failed\n", __func__,
			    ta_cmd == CMD_CIPHER_UPDATE ? "update" : "final");

	/* Update output length */
	if (!SET_OVERFLOW(op.params[2].tmpref.size, output_length))
		smw_crypto_set_cipher_output_len(args, output_length);
	else
		status = SMW_STATUS_OPERATION_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * cipher() - One-shot cipher operation.
 * @args: Cipher one-shot arguments.
 *
 * The one-shot operation is composed of an init step and a final step.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int cipher(void *args)
{
	int status = SMW_STATUS_OK;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct smw_op_context op_context = { 0 };
	unsigned int input_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Get output length feature */
	if (!smw_crypto_get_cipher_output(cipher_args)) {
		input_len = smw_crypto_get_cipher_input_len(cipher_args);

		/* Cipher output length is equal to input length */
		smw_crypto_set_cipher_output_len(cipher_args, input_len);

		goto end;
	}

	/*
	 * For multi-part operation, dynamic memory is allocated for operation
	 * context using the smw_allocate_context() API, whereas for single-shot
	 * operation, context is created on stack.
	 * Subsystem specific context is allocated during the initialization and
	 * released after the final operation.
	 */

	/* Cipher initialization */
	status = cipher_init(&op_context, cipher_args);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Cipher final */
	status = cipher_multi_part_common(&op_context, cipher_args,
					  CMD_CIPHER_FINAL);

end:
	if (op_context.op_state == CTX_OP_STATE_INIT &&
	    op_context.subsystem_context)
		SMW_UTILS_FREE(op_context.subsystem_context);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part(void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct smw_op_context *op_context = NULL;

	switch (cipher_args->op_step) {
	case SMW_OP_STEP_INIT:
		op_context = smw_crypto_get_cipher_init_op_context(cipher_args);
		status = cipher_init(op_context, cipher_args);
		break;

	case SMW_OP_STEP_UPDATE:
		op_context = smw_crypto_get_cipher_data_op_context(cipher_args);
		status = cipher_multi_part_common(op_context, cipher_args,
						  CMD_CIPHER_UPDATE);
		break;

	case SMW_OP_STEP_FINAL:
		op_context = smw_crypto_get_cipher_data_op_context(cipher_args);
		status = cipher_multi_part_common(op_context, cipher_args,
						  CMD_CIPHER_FINAL);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_cipher_handle(enum operation_id operation_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (operation_id) {
	case OPERATION_ID_CIPHER:
		*status = cipher(args);
		break;

	case OPERATION_ID_CIPHER_MULTI_PART:
		*status = cipher_multi_part(args);
		break;

	default:
		return false;
	}

	return true;
}
