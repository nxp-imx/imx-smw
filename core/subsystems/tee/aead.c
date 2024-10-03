// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "aead.h"
#include "tee.h"

#include "smw_status.h"
#include "operation_context.h"

#define TEE_AEAD_ALGO_ID(_key_type, _smw_aead_mode)                            \
	{                                                                      \
		.key_type = SMW_CONFIG_KEY_TYPE_ID_##_key_type,                \
		.aead_mode = SMW_CONFIG_AEAD_MODE_ID_##_smw_aead_mode,         \
		.tee_algo = TEE_ALG_##_key_type##_##_smw_aead_mode             \
	}

static const struct {
	enum smw_config_key_type_id key_type;
	enum smw_config_aead_mode_id aead_mode;
	uint32_t tee_algo;
} tee_aead_algo_id[] = {
	TEE_AEAD_ALGO_ID(AES, CCM),
	TEE_AEAD_ALGO_ID(AES, GCM),
};

static int get_tee_aead_algo_id(enum smw_config_key_type_id key_type,
				enum smw_config_aead_mode_id aead_mode,
				uint32_t *tee_algo)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(tee_aead_algo_id); i++) {
		if (key_type == tee_aead_algo_id[i].key_type &&
		    aead_mode == tee_aead_algo_id[i].aead_mode) {
			*tee_algo = tee_aead_algo_id[i].tee_algo;
			return SMW_STATUS_OK;
		}
	}

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

/**
 * get_tee_aead_operation_and_usage() - Get OPTEE operation and key usage
 * @smw_op: smw operation type
 * @tee_op: Pointer to optee operation type flag
 * @key_usage: Pointer to optee tee usage flag
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid configuration
 */
static int
get_tee_aead_operation_and_usage(enum smw_config_aead_op_type_id smw_op,
				 uint32_t *tee_op, unsigned int *key_usage)
{
	switch (smw_op) {
	case SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT:
		*tee_op = TEE_MODE_ENCRYPT;
		*key_usage = TEE_KEY_USAGE_ENCRYPT;
		break;

	case SMW_CONFIG_AEAD_OP_TYPE_ID_DECRYPT:
		*tee_op = TEE_MODE_DECRYPT;
		*key_usage = TEE_KEY_USAGE_DECRYPT;
		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

/**
 * set_aead_context() - Allocate and initialize AEAD subsystem specific context
 * @op_context: Pointer to operation context arguments structure
 * @args: Pointer to internal AEAD arguments structure
 * @context: Pointer to TEE context operation handle structure
 * @iv: initial vector
 *
 * This function initializes the members of operation context structure. It also
 * allocates memory to aead subsystem specific context and initializes it's
 * members.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE - Memory allocation failure
 */
static int set_aead_context(struct smw_op_context *op_context,
			    struct smw_crypto_aead_args *args,
			    struct shared_context *context, unsigned char *iv)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct aead_context *aead_ctx = NULL;

	unsigned int iv_len = 0;

	if (!iv || !op_context)
		goto end;

	op_context->op_id = SMW_CRYPTO_OP_ID_AEAD_MULTI_PART;

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		iv_len = smw_crypto_get_aead_user_iv_len(args);

		if (iv_len < smw_crypto_get_aead_iv_len(args))
			iv_len = smw_crypto_get_aead_iv_len(args);

		if (!iv_len)
			goto end;
	}

	aead_ctx = SMW_UTILS_CALLOC(1, sizeof(*aead_ctx));
	if (!aead_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(DEBUG,
			       "AEAD subsystem context allocation failure\n");
		goto end;
	}

	aead_ctx->tee_handle = context->handle;

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		aead_ctx->iv_len = iv_len;
		SMW_UTILS_MEMCPY(aead_ctx->iv, iv, iv_len);
	}

	op_context->subsystem_context = aead_ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_init(struct smw_op_context *op_context,
		     struct smw_crypto_aead_args *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	int res = SMW_STATUS_OK;
	unsigned int key_id = INVALID_KEY_ID;
	enum smw_config_key_type_id key_type = 0;
	struct aead_shared_params shared_params = { 0 };
	struct shared_context context = { 0 };
	unsigned int key_usage = 0;
	unsigned char iv[TEE_MAX_IV_LEN] = { 0 };
	unsigned char *user_iv = NULL;
	size_t user_iv_len = 0;
	size_t iv_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !op_context)
		goto end;

	/* Get key type as reference */
	key_type = args->key_desc.identifier.type_id;

	/*
	 * params[0] = IV
	 * params[1] = Key id as integer or as integer array
	 * params[2] = Pointer to aead_shared_params structure
	 * params[3] = Operation handle
	 */
	user_iv = smw_crypto_get_aead_user_iv(args);
	user_iv_len = smw_crypto_get_aead_user_iv_len(args);
	op.params[0].tmpref.buffer = iv;
	if (user_iv) {
		if (user_iv_len && user_iv_len <= TEE_MAX_IV_LEN)
			memcpy(iv, user_iv, user_iv_len);

		op.params[0].tmpref.size = user_iv_len;
	}

	/*
	 * To generate complete or partial IV, the user can set
	 * respectively, the input:
	 *  - init->user_iv_length = 0.
	 *  - init->user_iv_length < init->iv_length.
	 *
	 * Otherwise, the subsystem will use the user supplied IV.
	 *
	 */
	iv_len = smw_crypto_get_aead_iv_len(args);
	if (iv_len > TEE_MAX_IV_LEN) {
		status = SMW_STATUS_INVALID_IV_SIZE;
		goto end;
	}

	if (iv_len && user_iv_len < iv_len) {
		shared_params.fixed_iv_len = user_iv_len;

		op.params[0].tmpref.size = iv_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT,
						 TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_INOUT);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_INOUT);
	}

	/* Get OPTEE algorithm */
	status = get_tee_aead_algo_id(key_type, args->mode_id,
				      &shared_params.aead_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get OPTEE operation and key usage */
	status = get_tee_aead_operation_and_usage(args->op_type_id,
						  &shared_params.aead_op,
						  &key_usage);
	if (status != SMW_STATUS_OK)
		goto end;

	key_id = args->key_desc.identifier.id;

	/*
	 * If the key id is not valid, import the key first in
	 * TEE, then imported key is removed before leaving.
	 */
	if (key_id == INVALID_KEY_ID) {
		/* If a key is defined as buffer import it */
		status = tee_import_key_buffer(&args->key_desc, &key_id,
					       key_usage);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	op.params[1].value.a = key_id;

	if (MUL_OVERFLOW(smw_crypto_get_aead_tag_len(args), 8,
			 &shared_params.tag_len)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	shared_params.payload_len = smw_crypto_get_aead_plaintext_len(args);
	shared_params.aad_len = smw_crypto_get_aead_aad_len(args);

	op.params[2].tmpref.buffer = &shared_params;
	op.params[2].tmpref.size = sizeof(shared_params);
	op.params[3].tmpref.buffer = &context;
	op.params[3].tmpref.size = sizeof(context);

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_TEE);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_AEAD_INIT, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status == SMW_STATUS_OK)
		status = set_aead_context(op_context, args, &context, iv);

	key_id = args->key_desc.identifier.id;
	if (key_id == INVALID_KEY_ID) {
		key_id = op.params[1].value.a;

		/* Delete imported ephemeral key */
		res = tee_delete_key(key_id);
		status = (status == SMW_STATUS_OK) ? res : status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_update_aad(struct smw_op_context *op_context,
			   struct smw_crypto_aead_args *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	struct shared_context context = { 0 };
	struct aead_context *aead_ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op_context)
		goto end;

	aead_ctx = op_context->subsystem_context;
	if (!aead_ctx)
		goto end;

	context.handle = aead_ctx->tee_handle;

	/*
	 * Parameters for TEE_AEUpdateAAD
	 * params[0] = Operation handle
	 * params[1] = AAD data
	 * params[2] = None
	 * params[3] = None
	 */

	op.params[0].tmpref.buffer = &context;
	op.params[0].tmpref.size = sizeof(context);

	op.params[1].tmpref.size = smw_crypto_get_aead_aad_len(args);
	op.params[1].tmpref.buffer = smw_crypto_get_aead_aad(args);

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_NONE, TEEC_NONE);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_AEAD_UPDATE_AAD, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK, "%s: %s failed\n",
			    __func__, "TEE_AEUpdateAAD");

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static uint32_t get_tag_param_type(enum ta_commands ta_cmd)
{
	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL)
		return TEEC_MEMREF_TEMP_OUTPUT;
	else if (ta_cmd == CMD_AEAD_DECRYPT_FINAL)
		return TEEC_MEMREF_TEMP_INPUT;

	return TEEC_NONE;
}

/**
 * get_tee_input_data_len() - Return the length of the input data buffer only
 * @args: Pointer to internal AEAD argument structure
 * @ta_cmd: OPTEE command
 * @input_data_length: Pointer to hold the input data buffer length
 *
 * For encryption operation, it returns input data length
 * For decryption operation, it returns ciphertext length (excludes tag length)
 *
 * Return:
 * SMW_STATUS_OK
 * SMW_STATUS_INVALID_PARAM
 */
static unsigned int get_tee_input_data_len(struct smw_crypto_aead_args *args,
					   enum ta_commands ta_cmd,
					   unsigned int *input_data_length)
{
	int status = SMW_STATUS_OK;

	*input_data_length = smw_crypto_get_aead_input_len(args);

	if (ta_cmd == CMD_AEAD_DECRYPT_FINAL) {
		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (DEC_OVERFLOW(*input_data_length,
					 smw_crypto_get_aead_tag_len(args)))
				status = SMW_STATUS_INVALID_PARAM;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned with input length = %u\n",
		       __func__, *input_data_length);
	return status;
}

/**
 * get_tee_output_data_len() - Return the length of the output data buffer only
 * @args: Pointer to internal AEAD arguments
 * @ta_cmd: OPTEE command
 *
 * For encryption operation, it returns ciphertext length only (excludes tag length)
 * For decryption operation, it returns data length
 *
 * Return:
 * output data buffer length
 * 0
 */
static unsigned int get_tee_output_data_len(struct smw_crypto_aead_args *args,
					    enum ta_commands ta_cmd)
{
	unsigned int out_len = 0;

	out_len = smw_crypto_get_aead_output_len(args);

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL) {
		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (DEC_OVERFLOW(out_len,
					 smw_crypto_get_aead_tag_len(args)))
				out_len = 0;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned with output length = %u\n",
		       __func__, out_len);

	return out_len;
}

static int aead_multi_part_common(struct smw_op_context *op_context,
				  struct smw_crypto_aead_args *args,
				  enum ta_commands ta_cmd)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int output_length = 0;
	unsigned int input_length = 0;
	unsigned int tag_length = 0;
	unsigned char *output_iv = NULL;
	struct aead_context *aead_ctx = NULL;

	struct shared_context context = { 0 };

	TEEC_Operation op = { 0 };
	uint32_t param_type = TEEC_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!op_context)
		goto end;

	aead_ctx = op_context->subsystem_context;
	if (!aead_ctx)
		goto end;

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL) {
		if (smw_crypto_get_aead_output_iv_len(args) < aead_ctx->iv_len)
			goto end;

		output_iv = smw_crypto_get_aead_output_iv(args);
	}

	context.handle = aead_ctx->tee_handle;

	/*
	 * Parameters for TEE_AEUpdate
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = None
	 *
	 * Parameters for TEE_AEEncryptFinal/TEE_AEDecryptFinal
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = Tag
	 */

	param_type = get_tag_param_type(ta_cmd);
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT, param_type);

	op.params[0].tmpref.buffer = &context;
	op.params[0].tmpref.size = sizeof(context);
	op.params[1].tmpref.buffer = smw_crypto_get_aead_input(args);

	/*
	 * For final operation, TEE requires an input length set to 0 if input
	 * data buffer is NULL
	 */
	if (!op.params[1].tmpref.buffer) {
		op.params[1].tmpref.size = 0;
	} else {
		status = get_tee_input_data_len(args, ta_cmd, &input_length);
		if (status != SMW_STATUS_OK)
			goto end;

		op.params[1].tmpref.size = input_length;
	}

	op.params[2].tmpref.buffer = smw_crypto_get_aead_output(args);

	/* Set output length to 0 if output data buffer is NULL */
	if (!op.params[2].tmpref.buffer)
		op.params[2].tmpref.size = 0;
	else
		op.params[2].tmpref.size =
			get_tee_output_data_len(args, ta_cmd);

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL ||
	    ta_cmd == CMD_AEAD_DECRYPT_FINAL) {
		if (op.params[2].tmpref.size == 0 &&
		    op.params[1].tmpref.size != 0) {
			op.params[3].tmpref.size = 0;
			op.params[3].tmpref.buffer = NULL;
		} else {
			op.params[3].tmpref.buffer =
				smw_crypto_get_aead_tag(args);
			op.params[3].tmpref.size =
				smw_crypto_get_aead_tag_len(args);
		}
	}

	/* Invoke TA */
	status = execute_tee_cmd(ta_cmd, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: AEAD %s failed\n", __func__,
			    ta_cmd == CMD_AEAD_UPDATE ? "update" : "final");

	/* Update output length */
	if (!SET_OVERFLOW(op.params[2].tmpref.size, output_length)) {
		smw_crypto_set_aead_output_len(args, output_length);
	} else {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL) {
		if (!SET_OVERFLOW(op.params[3].tmpref.size, tag_length))
			smw_crypto_set_aead_tag_len(args, tag_length);
		else
			status = SMW_STATUS_OPERATION_FAILURE;

		/*
		 * For encryption,
		 * if dedicated tag is set,
		 * output_length = ciphertext length
		 *
		 * if dedicated tag is not set,
		 * output_length = ciphertext length + tag length
		 *
		 */

		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (!INC_OVERFLOW(output_length, tag_length)) {
				smw_crypto_set_aead_output_len(args,
							       output_length);
			} else {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}

		if (status != SMW_STATUS_OK &&
		    status != SMW_STATUS_OUTPUT_TOO_SHORT)
			goto end;

		smw_crypto_set_aead_output_iv_len(args, aead_ctx->iv_len);

		/* Copy user provided IV buffer to output IV */
		if (status == SMW_STATUS_OK && output_iv && aead_ctx->iv_len)
			SMW_UTILS_MEMCPY(output_iv, aead_ctx->iv,
					 aead_ctx->iv_len);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_one_shot(void *args)
{
	int status = SMW_STATUS_OK;
	struct smw_crypto_aead_args *aead_args = args;
	struct smw_op_context op_context = { 0 };
	enum ta_commands ta_cmd = CMD_AEAD_ENCRYPT_FINAL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * For multi-part operation, dynamic memory is allocated for operation
	 * context using the smw_allocate_context() API, whereas for single-shot
	 * operation, context is created on stack.
	 * Subsystem specific context is allocated during the initialization and
	 * released after the final operation or if the aead_update_aad has returned
	 * error.
	 */

	/* AE initialization */
	status = aead_init(&op_context, aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Update AAD */
	if (smw_crypto_get_aead_aad(aead_args) &&
	    smw_crypto_get_aead_aad_len(aead_args)) {
		status = aead_update_aad(&op_context, aead_args);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_DECRYPT)
		ta_cmd = CMD_AEAD_DECRYPT_FINAL;

	/* AE final */
	status = aead_multi_part_common(&op_context, aead_args, ta_cmd);

end:
	if (op_context.op_state == CTX_OP_STATE_INIT &&
	    op_context.subsystem_context)
		SMW_UTILS_FREE(op_context.subsystem_context);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_multi_part(void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_crypto_aead_args *aead_args = args;
	struct smw_op_context *op_context = NULL;

	switch (aead_args->op_step) {
	case SMW_OP_STEP_INIT:
		op_context = smw_crypto_get_aead_init_op_context(aead_args);
		status = aead_init(op_context, aead_args);
		break;

	case SMW_OP_STEP_UPDATE:
		op_context = smw_crypto_get_aead_data_op_context(aead_args);
		status = aead_multi_part_common(op_context, aead_args,
						CMD_AEAD_UPDATE);
		break;

	case SMW_OP_STEP_FINAL:
		op_context = smw_crypto_get_aead_data_op_context(aead_args);
		if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
			status = aead_multi_part_common(op_context, aead_args,
							CMD_AEAD_ENCRYPT_FINAL);
		else
			status = aead_multi_part_common(op_context, aead_args,
							CMD_AEAD_DECRYPT_FINAL);

		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_aead_handle(enum operation_id operation_id, void *args, int *status)
{
	struct smw_op_context *ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (operation_id) {
	case OPERATION_ID_AEAD:
		*status = aead_one_shot(args);
		break;

	case OPERATION_ID_AEAD_MULTI_PART:
		*status = aead_multi_part(args);
		break;

	case OPERATION_ID_AEAD_UPDATE_AAD:
		ctx = smw_crypto_get_aead_aad_op_context(args);
		*status = aead_update_aad(ctx, args);
		break;

	default:
		return false;
	}

	return true;
}
