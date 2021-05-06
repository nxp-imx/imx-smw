// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "smw_osal.h"
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
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(tee_cipher_algo_id); i++) {
		if (key_type == tee_cipher_algo_id[i].key_type &&
		    cipher_mode == tee_cipher_algo_id[i].cipher_mode) {
			*tee_algo = tee_cipher_algo_id[i].tee_algo;
			return SMW_STATUS_OK;
		}
	}

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

static int get_tee_cipher_operation(enum smw_config_cipher_op_type_id smw_op,
				    uint32_t *tee_op)
{
	switch (smw_op) {
	case SMW_CONFIG_CIPHER_OP_ID_ENCRYPT:
		*tee_op = TEE_MODE_ENCRYPT;
		break;

	case SMW_CONFIG_CIPHER_OP_ID_DECRYPT:
		*tee_op = TEE_MODE_DECRYPT;
		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

static unsigned int get_nb_key_id(struct smw_crypto_cipher_args *args)
{
	unsigned int i;
	unsigned int nb_ids = 0;

	for (i = 0; i < args->nb_keys; i++) {
		if (args->keys_desc[i]->identifier.id)
			nb_ids++;
	}

	return nb_ids;
}

static unsigned int get_nb_key_buffer(struct smw_crypto_cipher_args *args)
{
	unsigned int i;
	unsigned int nb_buffers = 0;

	/* Key is defined as buffer if ID is not set and buffer set */
	for (i = 0; i < args->nb_keys; i++) {
		if (!args->keys_desc[i]->identifier.id &&
		    smw_crypto_get_cipher_key(args, i))
			nb_buffers++;
	}

	return nb_buffers;
}

static int import_key_buffer(struct smw_crypto_cipher_args *args,
			     enum smw_config_key_type_id key_type,
			     uint32_t **key_ids, unsigned int *nb_ids)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	unsigned int i;
	struct keymgr_shared_params import_shared_params = { 0 };
	uint32_t *ids_array = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*nb_ids = get_nb_key_buffer(args);

	/* No key is defined as buffer, no key to import */
	if (!*nb_ids)
		goto end;

	/* Caller must free this memory */
	ids_array = SMW_UTILS_MALLOC(*nb_ids * sizeof(uint32_t));
	if (!ids_array) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	*key_ids = ids_array;

	/* Key type is common for all keys */
	status = tee_convert_key_type(key_type, &import_shared_params.key_type);
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

	for (i = 0; i < *nb_ids; i++) {
		import_shared_params.security_size =
			args->keys_desc[i]->identifier.security_size;

		op.params[1].tmpref.buffer = smw_crypto_get_cipher_key(args, i);
		op.params[1].tmpref.size =
			smw_crypto_get_cipher_key_len(args, i);

		/* Invoke TA */
		status = execute_tee_cmd(CMD_IMPORT_KEY, &op);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n",
				       __func__);
			goto end;
		}

		ids_array[i] = import_shared_params.id;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int delete_imported_keys(uint32_t *key_ids, unsigned int nb_keys)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_OK;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_ids)
		goto end;

	/* params[0] = Key ID */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	for (i = 0; i < nb_keys; i++) {
		op.params[0].value.a = key_ids[i];

		/* Invoke TA */
		status = execute_tee_cmd(CMD_DELETE_KEY, &op);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_init(struct smw_crypto_cipher_args *args)
{
	TEEC_Operation op = { 0 };
	int status;
	unsigned int nb_key_ids;
	unsigned int nb_ephemeral_ids = 0;
	uint32_t param2_type = TEEC_NONE;
	uint32_t *ephemeral_key_ids = NULL;
	enum smw_config_key_type_id key_type;
	struct shared_context context = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Get 1st key type as reference */
	key_type = args->keys_desc[0]->identifier.type_id;

	/* Get OPTEE algorithm */
	status = get_tee_cipher_algo_id(key_type, args->mode_id,
					&op.params[0].value.a);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get OPTEE operation */
	status = get_tee_cipher_operation(args->op_id, &op.params[0].value.b);
	if (status != SMW_STATUS_OK)
		goto end;

	/* If some keys are defined as buffer import them */
	status = import_key_buffer(args, key_type, &ephemeral_key_ids,
				   &nb_ephemeral_ids);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get number of keys defined as key ID */
	nb_key_ids = get_nb_key_id(args);

	/*
	 * params[0] = TEE Algo ID, TEE Operation
	 * params[1] = Key ids as integer or as integer array
	 * params[2] = IV or none
	 * params[3] = Operation handle
	 */

	/*
	 * For one or two key, IDs are shared as integer.
	 * If in the future, more keys are used this parameter can be used as a
	 * key IDs array.
	 */
	if (args->nb_keys <= 2) {
		if (nb_ephemeral_ids) {
			op.params[1].value.a = ephemeral_key_ids[0];

			if (nb_ephemeral_ids == 2)
				op.params[1].value.b = ephemeral_key_ids[1];
		}

		if (nb_key_ids) {
			if (!nb_ephemeral_ids)
				op.params[1].value.a =
					smw_crypto_get_cipher_key_id(args, 0);

			if (nb_key_ids == 2)
				op.params[1].value.b =
					smw_crypto_get_cipher_key_id(args, 1);
		}
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

	args->handle = context.handle;

	/* Delete imported ephemeral keys */
	if (status != SMW_STATUS_OK)
		/* TA cipher initialization error code is returned */
		(void)delete_imported_keys(ephemeral_key_ids, nb_ephemeral_ids);
	else
		status = delete_imported_keys(ephemeral_key_ids,
					      nb_ephemeral_ids);

end:
	if (ephemeral_key_ids)
		SMW_UTILS_FREE(ephemeral_key_ids);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part_common(struct smw_crypto_cipher_args *args,
				    unsigned int ta_cmd)
{
	TEEC_Operation op = { 0 };
	int status;
	struct shared_context context;

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
	smw_crypto_set_cipher_output_len(args, op.params[2].tmpref.size);

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
	int status;
	struct smw_crypto_cipher_args *cipher_args = args;
	struct smw_op_context op_context = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Cipher initialization */
	status = cipher_init(cipher_args);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Cipher final */
	op_context.handle = cipher_args->handle;
	smw_crypto_set_cipher_op_context(cipher_args, &op_context);

	status = cipher_multi_part_common(cipher_args, CMD_CIPHER_FINAL);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int cipher_multi_part(void *args)
{
	int status;
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
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
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
