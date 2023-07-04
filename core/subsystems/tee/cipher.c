// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
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
			   TEE_CIPHER_ALGO_ID(DES3, ECB, ECB_NOPAD) };

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

static int
get_tee_cipher_operation_and_usage(enum smw_config_cipher_op_type_id smw_op,
				   uint32_t *tee_op, unsigned int *key_usage)
{
	switch (smw_op) {
	case SMW_CONFIG_CIPHER_OP_ID_ENCRYPT:
		*tee_op = TEE_MODE_ENCRYPT;
		*key_usage = TEE_KEY_USAGE_ENCRYPT;
		break;

	case SMW_CONFIG_CIPHER_OP_ID_DECRYPT:
		*tee_op = TEE_MODE_DECRYPT;
		*key_usage = TEE_KEY_USAGE_DECRYPT;
		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

static int import_key_buffer(struct smw_keymgr_descriptor *key,
			     unsigned int *key_id, unsigned int key_usage)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	struct keymgr_shared_params import_shared_params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Key type is common for all keys */
	status = tee_convert_key_type(key->identifier.type_id,
				      &import_shared_params.key_type);
	if (status != SMW_STATUS_OK)
		goto end;

	/*
	 * params[0]: Pointer to import shared params structure.
	 * params[1]: Private key buffer.
	 * params[2]: None.
	 * params[3]: None.
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = &import_shared_params;
	op.params[0].tmpref.size = sizeof(import_shared_params);

	import_shared_params.security_size = key->identifier.security_size;
	import_shared_params.key_usage = key_usage;

	op.params[1].tmpref.buffer = smw_keymgr_get_private_data(key);
	op.params[1].tmpref.size = smw_keymgr_get_private_length(key);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_IMPORT_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto end;
	}

	*key_id = import_shared_params.id;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_imported_keys(unsigned int key_id)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (key_id == INVALID_KEY_ID)
		goto end;

	/* params[0] = Key ID */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].value.a = key_id;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_DELETE_KEY, &op);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_init(struct smw_crypto_cipher_args *args)
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
	status = get_tee_cipher_operation_and_usage(args->op_id,
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
			status = import_key_buffer(args->keys_desc[key_idx],
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

	op.params[3].tmpref.buffer = &context;
	op.params[3].tmpref.size = sizeof(context);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_CIPHER_INIT, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status == SMW_STATUS_OK) {
		smw_crypto_set_cipher_init_handle(args, context.handle);
		smw_crypto_set_cipher_ctx_reserved(args, tee_get_ctx_ops());
	}

	/* Delete imported ephemeral keys and update operation context */
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

			res = delete_imported_keys(key_id);
			status = (status == SMW_STATUS_OK) ? res : status;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part_common(struct smw_crypto_cipher_args *args,
				    enum ta_commands ta_cmd)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	struct shared_context context = { 0 };
	unsigned int output_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	context.handle = smw_crypto_get_cipher_op_handle(args);

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

	/*
	 * For final operation, TEE requires an input length set to 0 if input
	 * data buffer is NULL
	 */
	if (!op.params[1].tmpref.buffer)
		op.params[1].tmpref.size = 0;
	else
		op.params[1].tmpref.size =
			smw_crypto_get_cipher_input_len(args);

	op.params[2].tmpref.buffer = smw_crypto_get_cipher_output(args);

	/*
	 * For final operation, TEE requires an output length set to 0 if output
	 * data buffer is NULL
	 */
	if (!op.params[2].tmpref.buffer)
		op.params[2].tmpref.size = 0;
	else
		op.params[2].tmpref.size =
			smw_crypto_get_cipher_output_len(args);

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

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_crypto_set_cipher_init_op_context(cipher_args, &op_context);

	/* Cipher initialization */
	status = cipher_init(cipher_args);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Cipher final */
	smw_crypto_set_cipher_data_op_context(cipher_args, &op_context);

	status = cipher_multi_part_common(cipher_args, CMD_CIPHER_FINAL);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part(void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_crypto_cipher_args *cipher_args = args;

	switch (cipher_args->op_step) {
	case SMW_OP_STEP_INIT:
		status = cipher_init(cipher_args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = cipher_multi_part_common(cipher_args,
						  CMD_CIPHER_UPDATE);
		break;

	case SMW_OP_STEP_FINAL:
		status =
			cipher_multi_part_common(cipher_args, CMD_CIPHER_FINAL);
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
