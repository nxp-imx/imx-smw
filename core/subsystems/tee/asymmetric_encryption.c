// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "asymmetric_encryption.h"
#include "tee.h"

#define ASYMM_ENC_MODE_ID(_type, _id)                                          \
	{                                                                      \
		.smw_id = SMW_CONFIG_ASYMM_ENC_MODE_ID_##_type,                \
		.tee_id = TEE_ASYMM_ENC_MODE_##_id                             \
	}

/**
 * struct - Asymmetric encryption padding mode IDs
 * @smw_id: Asymmetric encryption padding mode ID as defined in SMW.
 * @tee_id: Asymmetric encryption padding mode ID as defined in TEE subsystem.
 */
static const struct {
	enum smw_config_asymm_enc_mode_id smw_id;
	enum tee_asymm_enc_mode tee_id;
} asymm_enc_mode_ids[] = { ASYMM_ENC_MODE_ID(PKCS1_1_5, RSAES_PKCS1_V1_5),
			   ASYMM_ENC_MODE_ID(OAEP, RSAES_PKCS1_OAEP),
			   { SMW_CONFIG_ASYMM_ENC_MODE_ID_NO_PAD,
			     TEE_ASYMM_ENC_MODE_RSA_NOPAD } };

static int tee_get_asymm_enc_mode_id(enum smw_config_asymm_enc_mode_id smw_id,
				     enum tee_asymm_enc_mode *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(asymm_enc_mode_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < array_size; i++) {
		if (asymm_enc_mode_ids[i].smw_id == smw_id) {
			*tee_id = asymm_enc_mode_ids[i].tee_id;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_pub_key_buffer_len(enum smw_keymgr_format_id format_id,
				  unsigned char *pub_key_buffer,
				  unsigned int pub_key_buffer_len,
				  unsigned int *hex_pub_buffer_len)
{
	int status = SMW_STATUS_OK;

	/* Key ID is set */
	if (format_id == SMW_KEYMGR_FORMAT_ID_INVALID)
		goto exit;

	status = smw_keymgr_get_hex_key_buffer_len(format_id, pub_key_buffer,
						   pub_key_buffer_len,
						   hex_pub_buffer_len);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * asymm_encrypt_decrypt() - Perform asymmetric encryption or decryption.
 * @args: Internal asymmetric encryption arguments structure.
 * @op_id: OPERATION_ID_ASYMM_ENCRYPT or OPERATION_ID_ASYMM_DECRYPT.
 *
 * Return:
 * SMW_STATUS_OK		        - Success.
 * SMW_STATUS_INVALID_PARAM	    - One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int asymm_encrypt_decrypt(struct smw_crypto_asymm_enc_args *args,
				 enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation operation = { 0 };
	TEEC_SharedMemory shm = { 0 };

	struct smw_keymgr_descriptor *key_desc = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct asymm_enc_shared_params *shared_params = NULL;
	unsigned int shared_params_size =
		sizeof(struct asymm_enc_shared_params);

	unsigned int output_len = 0;
	unsigned int salt_len = 0;
	unsigned char *salt = NULL;
	unsigned int pub_key_len = 0;
	unsigned char *pub_key = NULL;

	uint32_t param0_type = TEEC_NONE;

	enum tee_key_type key_type_id = TEE_KEY_TYPE_ID_INVALID;
	enum smw_keymgr_privacy_id key_privacy = SMW_KEYMGR_PRIVACY_ID_INVALID;

	enum ta_commands cmd_id = CMD_ASYMM_DECRYPT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_desc = &args->key_desc;
	key_identifier = &key_desc->identifier;

	status = tee_convert_key_type(key_identifier,
				      SMW_CONFIG_HASH_ALGO_ID_INVALID,
				      &key_type_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (key_type_id != TEE_KEY_TYPE_ID_RSA) {
		SMW_DBG_PRINTF(ERROR, "Only RSA key type is supported.\n");
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	if (args->attrs.mode_id == SMW_CONFIG_ASYMM_ENC_MODE_ID_OAEP) {
		salt_len = smw_crypto_get_asymm_enc_salt_len(args);
		salt = smw_crypto_get_asymm_enc_salt(args);

		if (salt && salt_len) {
			if (ADD_OVERFLOW(shared_params_size, salt_len,
					 &shared_params_size)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}
		}
	}

	shared_params = SMW_UTILS_CALLOC(1, shared_params_size);
	if (!shared_params) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	shared_params->salt_length = salt_len;

	if (salt && salt_len)
		SMW_UTILS_MEMCPY(shared_params->salt, salt, salt_len);

	status = tee_convert_hash_algorithm_id(args->attrs.hash_id,
					       &shared_params->hash_algorithm);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = tee_get_asymm_enc_mode_id(args->attrs.mode_id,
					   &shared_params->mode);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * params[0] = Key shared memory or none
	 * params[1] = Pointer to asymmetric encrypt/decrypt shared params structure
	 * params[2] = Input buffer and length
	 * params[3] = Output buffer and length
	 */

	switch (op_id) {
	case OPERATION_ID_ASYMM_ENCRYPT:
		if (key_desc->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			param0_type = TEEC_MEMREF_PARTIAL_INPUT;
			key_privacy = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
		}

		cmd_id = CMD_ASYMM_ENCRYPT;
		break;

	case OPERATION_ID_ASYMM_DECRYPT:
		if (key_desc->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			param0_type = TEEC_MEMREF_PARTIAL_INPUT;
			key_privacy = SMW_KEYMGR_PRIVACY_ID_PAIR;
		}

		cmd_id = CMD_ASYMM_DECRYPT;
		break;

	default:
		goto exit;
	}

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT) {
		pub_key = smw_keymgr_get_public_data(key_desc);
		pub_key_len = smw_keymgr_get_public_length(key_desc);

		if (!pub_key || !pub_key_len) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}

		status = get_pub_key_buffer_len(key_desc->format_id, pub_key,
						pub_key_len,
						&shared_params->pub_key_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = copy_keys_to_shm(&shm, key_desc, key_privacy);
		if (status != SMW_STATUS_OK)
			goto exit;

		operation.params[0].memref.parent = &shm;
		operation.params[0].memref.offset = 0;
		operation.params[0].memref.size = shm.size;
	} else {
		shared_params->id = key_identifier->id;
	}

	shared_params->key_type = key_type_id;
	shared_params->security_size = key_identifier->security_size;

	operation.paramTypes =
		TEEC_PARAM_TYPES(param0_type, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT);

	operation.params[1].tmpref.buffer = shared_params;
	operation.params[1].tmpref.size = shared_params_size;
	operation.params[2].tmpref.buffer =
		smw_crypto_get_asymm_enc_input(args);
	operation.params[2].tmpref.size =
		smw_crypto_get_asymm_enc_input_len(args);
	operation.params[3].tmpref.buffer =
		smw_crypto_get_asymm_enc_output(args);
	operation.params[3].tmpref.size =
		smw_crypto_get_asymm_enc_output_len(args);

	/* Invoke TA */
	status = execute_tee_cmd(cmd_id, &operation);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto exit;

	if (!SET_OVERFLOW(operation.params[3].tmpref.size, output_len)) {
		smw_crypto_set_asymm_enc_output_len(args, output_len);

		SMW_DBG_PRINTF(DEBUG, "Output length = %u\n", output_len);
	} else {
		status = SMW_STATUS_OPERATION_FAILURE;
	}

exit:
	if (shared_params)
		free(shared_params);

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT)
		TEEC_ReleaseSharedMemory(&shm);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_asymm_encrypt_decrypt_handle(enum operation_id op_id, void *args,
				      int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_ASYMM_ENCRYPT:
	case OPERATION_ID_ASYMM_DECRYPT:
		*status = asymm_encrypt_decrypt(args, op_id);
		break;
	default:
		return false;
	}

	return true;
}
