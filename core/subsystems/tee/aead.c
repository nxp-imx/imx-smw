// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "aead.h"
#include "tee.h"

#include "smw_status.h"

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
	case SMW_CONFIG_AEAD_OP_ID_ENCRYPT:
		*tee_op = TEE_MODE_ENCRYPT;
		*key_usage = TEE_KEY_USAGE_ENCRYPT;
		break;

	case SMW_CONFIG_AEAD_OP_ID_DECRYPT:
		*tee_op = TEE_MODE_DECRYPT;
		*key_usage = TEE_KEY_USAGE_DECRYPT;
		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

static int aead_init(struct smw_crypto_aead_args *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	int res = SMW_STATUS_OK;
	unsigned int key_id = INVALID_KEY_ID;
	enum smw_config_key_type_id key_type = 0;
	struct aead_shared_params shared_params = { 0 };
	struct shared_context context = { 0 };
	unsigned int key_usage = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Get key type as reference */
	key_type = args->key_desc.identifier.type_id;

	/*
	 * params[0] = IV
	 * params[1] = Key id as integer or as integer array
	 * params[2] = Pointer to aead_shared_params structure
	 * params[3] = Operation handle
	 */
	if (smw_crypto_get_iv(args)) {
		op.params[0].tmpref.buffer = smw_crypto_get_iv(args);
		op.params[0].tmpref.size = smw_crypto_get_iv_len(args);
	}

	/* Get OPTEE algorithm */
	status = get_tee_aead_algo_id(key_type, args->mode_id,
				      &shared_params.aead_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get OPTEE operation and key usage */
	status = get_tee_aead_operation_and_usage(args->op_id,
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

	if (MUL_OVERFLOW(smw_crypto_get_tag_len(args), 8,
			 &shared_params.tag_len)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	shared_params.payload_len = smw_crypto_get_plaintext_len(args);
	shared_params.aad_len = smw_crypto_get_aad_len(args);

	op.params[2].tmpref.buffer = &shared_params;
	op.params[2].tmpref.size = sizeof(shared_params);
	op.params[3].tmpref.buffer = &context;
	op.params[3].tmpref.size = sizeof(context);

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT,
				 TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INOUT);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_AEAD_INIT, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status == SMW_STATUS_OK) {
		smw_crypto_set_init_handle(args, context.handle);
		smw_crypto_set_ctx_reserved(args, tee_get_ctx_ops());
	}

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

static int aead_update_aad(struct smw_crypto_aead_args *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	struct shared_context context = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	context.handle = smw_crypto_get_op_handle(args);

	/*
	 * Parameters for TEE_AEUpdateAAD
	 * params[0] = Operation handle
	 * params[1] = AAD data
	 * params[2] = None
	 * params[3] = None
	 */

	op.params[0].tmpref.buffer = &context;
	op.params[0].tmpref.size = sizeof(context);

	op.params[1].tmpref.size = smw_crypto_get_aad_len(args);
	op.params[1].tmpref.buffer = smw_crypto_get_aad(args);

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_NONE, TEEC_NONE);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_AEAD_UPDATE_AAD, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK, "%s: %s failed\n",
			    __func__, "TEE_AEUpdateAAD");

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
	unsigned int data_len = 0;

	data_len = smw_crypto_get_input_len(args);

	if (ta_cmd == CMD_AEAD_DECRYPT_FINAL) {
		if (DEC_OVERFLOW(data_len, smw_crypto_get_tag_len(args)))
			status = SMW_STATUS_INVALID_PARAM;
	}

	*input_data_length = data_len;
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

	out_len = smw_crypto_get_output_len(args);

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL) {
		if (DEC_OVERFLOW(out_len, smw_crypto_get_tag_len(args)))
			out_len = 0;
	}

	return out_len;
}

static int aead_multi_part_common(struct smw_crypto_aead_args *args,
				  enum ta_commands ta_cmd)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	struct shared_context context = { 0 };
	unsigned int output_length = 0;
	unsigned int input_length = 0;
	unsigned int tag_length = 0;
	uint32_t param_type = TEEC_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	context.handle = smw_crypto_get_op_handle(args);

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
	op.params[1].tmpref.buffer = smw_crypto_get_input(args);

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

	op.params[2].tmpref.buffer = smw_crypto_get_output(args);

	/* Set output length to 0 if output data buffer is NULL */
	if (!op.params[2].tmpref.buffer)
		op.params[2].tmpref.size = 0;
	else
		op.params[2].tmpref.size =
			get_tee_output_data_len(args, ta_cmd);

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL ||
	    ta_cmd == CMD_AEAD_DECRYPT_FINAL) {
		if (op.params[2].tmpref.size == 0) {
			op.params[3].tmpref.size = 0;
			op.params[3].tmpref.buffer = NULL;
		} else {
			op.params[3].tmpref.buffer = smw_crypto_get_tag(args);
			op.params[3].tmpref.size = smw_crypto_get_tag_len(args);
		}
	}

	/* Invoke TA */
	status = execute_tee_cmd(ta_cmd, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: AEAD %s failed\n", __func__,
			    ta_cmd == CMD_AEAD_UPDATE ? "update" : "final");

	/* Update output length */
	if (!SET_OVERFLOW(op.params[2].tmpref.size, output_length)) {
		smw_crypto_set_output_len(args, output_length);
	} else {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	if (ta_cmd == CMD_AEAD_ENCRYPT_FINAL) {
		if (!SET_OVERFLOW(op.params[3].tmpref.size, tag_length))
			smw_crypto_set_tag_len(args, tag_length);
		else
			status = SMW_STATUS_OPERATION_FAILURE;

		/* For encryption, output_length = ciphertext length + tag length */
		if (!INC_OVERFLOW(output_length, tag_length)) {
			smw_crypto_set_output_len(args, output_length);
		} else {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}
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

	smw_crypto_set_init_op_context(aead_args, &op_context);

	/* AE initialization */
	status = aead_init(aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_crypto_set_data_op_context(aead_args, &op_context);

	/* Update AAD */
	status = aead_update_aad(aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	if (aead_args->op_id == SMW_CONFIG_AEAD_OP_ID_DECRYPT)
		ta_cmd = CMD_AEAD_DECRYPT_FINAL;

	/* AE final */
	status = aead_multi_part_common(aead_args, ta_cmd);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_multi_part(void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_crypto_aead_args *aead_args = args;

	switch (aead_args->op_step) {
	case SMW_OP_STEP_INIT:
		status = aead_init(aead_args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = aead_multi_part_common(aead_args, CMD_AEAD_UPDATE);
		break;

	case SMW_OP_STEP_FINAL:
		if (aead_args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT)
			status = aead_multi_part_common(aead_args,
							CMD_AEAD_ENCRYPT_FINAL);
		else
			status = aead_multi_part_common(aead_args,
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
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (operation_id) {
	case OPERATION_ID_AEAD:
		*status = aead_one_shot(args);
		break;

	case OPERATION_ID_AEAD_MULTI_PART:
		*status = aead_multi_part(args);
		break;

	case OPERATION_ID_AEAD_AAD:
		*status = aead_update_aad(args);
		break;

	default:
		return false;
	}

	return true;
}
