// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "tee.h"

#define SIGNATURE_TYPE_ID(_type, _id)                                          \
	{                                                                      \
		.smw_id = SMW_CONFIG_SIGN_TYPE_ID_##_type,                     \
		.tee_id = TEE_SIGNATURE_TYPE_##_id                             \
	}

/**
 * struct - Signature type IDs
 * @smw_id: Signature type ID as defined in SMW.
 * @tee_id: Signature type ID as defined in TEE subsystem.
 */
static const struct {
	enum smw_config_sign_type_id smw_id;
	enum tee_signature_type tee_id;
} signature_type_ids[] = {
	SIGNATURE_TYPE_ID(DEFAULT, DEFAULT),
	SIGNATURE_TYPE_ID(PKCS1_1_5, RSASSA_PKCS1_V1_5),
	SIGNATURE_TYPE_ID(PSS, RSASSA_PSS),
	SIGNATURE_TYPE_ID(PURE_EDDSA, PURE_EDDSA),
	SIGNATURE_TYPE_ID(EDDSA_PH, EDDSA_PH),
	SIGNATURE_TYPE_ID(EDDSA_CTX, EDDSA_CTX),
};

static int tee_convert_signature_type_id(enum smw_config_sign_type_id smw_id,
					 enum tee_signature_type *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(signature_type_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < array_size; i++) {
		if (signature_type_ids[i].smw_id == smw_id) {
			*tee_id = signature_type_ids[i].tee_id;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_public_key_buffer(struct smw_keymgr_descriptor *key_desc,
				 TEEC_Parameter *param,
				 unsigned char **hex_public_key)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int public_key_len = smw_keymgr_get_public_length(key_desc);
	unsigned char *public_key = smw_keymgr_get_public_data(key_desc);
	unsigned int hex_public_key_len = 0;

	if (!public_key_len || !public_key)
		goto end;

	status = smw_keymgr_set_hex_key_buffer(key_desc->format_id, public_key,
					       public_key_len, hex_public_key,
					       &hex_public_key_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_public_key_len, param->tmpref.size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	param->tmpref.buffer = *hex_public_key;

end:
	return status;
}

static int get_pub_key_hex_len(struct smw_keymgr_descriptor *key_desc,
			       unsigned int *hex_buffer_len)
{
	unsigned int pub_size = smw_keymgr_get_public_length(key_desc);
	unsigned char *pub_buffer = smw_keymgr_get_public_data(key_desc);

	return smw_keymgr_get_hex_key_buffer_len(key_desc->format_id,
						 pub_buffer, pub_size,
						 hex_buffer_len);
}

/**
 * sign_verify() - Generate or verify a signature.
 * @args: Sign or verify arguments.
 * @op_id: OPERATION_ID_SIGN or OPERATION_ID_VERIFY.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int sign_verify(struct smw_crypto_sign_verify_args *args,
		       enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation operation = { 0 };
	TEEC_SharedMemory shm = { 0 };

	struct smw_keymgr_descriptor *key_descriptor = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct smw_sign_verify_attributes *sign_attrs = NULL;
	struct sign_verify_shared_params *shared_params = NULL;
	unsigned int shared_params_size =
		sizeof(struct sign_verify_shared_params);
	unsigned char *ctx = NULL;
	unsigned int ctx_length = 0;
	unsigned int sign_length = 0;
	unsigned char *hex_pub_key = NULL;

	uint32_t param0_type = TEEC_NONE;
	uint32_t param3_type = TEEC_NONE;

	enum tee_key_type key_type_id = TEE_KEY_TYPE_ID_INVALID;
	enum smw_keymgr_privacy_id key_privacy = SMW_KEYMGR_PRIVACY_ID_INVALID;

	enum ta_commands cmd_id = CMD_VERIFY;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_descriptor = &args->key_descriptor;
	key_identifier = &key_descriptor->identifier;
	sign_attrs = &args->attributes;

	status = tee_convert_key_type(key_identifier,
				      SMW_CONFIG_HASH_ALGO_ID_INVALID,
				      &key_type_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_RSA) {
		/*
		 * Signature type is mandatory.
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (sign_attrs->type_id == SMW_CONFIG_SIGN_TYPE_ID_DEFAULT) {
			SMW_DBG_PRINTF(ERROR, "No signature type set\n");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		} else if (sign_attrs->type_id ==
				   SMW_CONFIG_SIGN_TYPE_ID_PKCS1_1_5 &&
			   sign_attrs->salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       "RSA PKCS1_V1_5");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}

	} else if (sign_attrs->algo_id == SMW_CONFIG_SIGN_ALGO_ID_EDDSA) {
		ctx = smw_sign_verify_get_eddsactx_buf(args);
		ctx_length = smw_sign_verify_get_eddsactx_len(args);

		if (ctx && ctx_length) {
			if (ADD_OVERFLOW(shared_params_size, ctx_length,
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

	status = tee_convert_hash_algorithm_id(sign_attrs->hash_id,
					       &shared_params->hash_algorithm);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = tee_convert_signature_type_id(sign_attrs->type_id,
					       &shared_params->signature_type);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * params[0] = Key buffer or key shared memory or none
	 * params[1] = Pointer to sign verify shared params structure
	 * params[2] = Message buffer and message length
	 * params[3] = Signature buffer and signature length
	 */

	switch (op_id) {
	case OPERATION_ID_SIGN:
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			param0_type = TEEC_MEMREF_PARTIAL_INPUT;
			key_privacy = SMW_KEYMGR_PRIVACY_ID_PAIR;
		}

		param3_type = TEEC_MEMREF_TEMP_OUTPUT;
		cmd_id = CMD_SIGN;
		break;

	case OPERATION_ID_VERIFY:
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			if (sign_attrs->algo_id ==
			    SMW_CONFIG_SIGN_ALGO_ID_RSA) {
				param0_type = TEEC_MEMREF_PARTIAL_INPUT;
				key_privacy = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
			} else {
				/*
				 * Verify operation with a non RSA key doesn't
				 * require shared memory
				 */
				param0_type = TEEC_MEMREF_TEMP_INPUT;
			}
		}

		param3_type = TEEC_MEMREF_TEMP_INPUT;
		cmd_id = CMD_VERIFY;
		break;

	default:
		goto exit;
	}

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT) {
		status = copy_keys_to_shm(&shm, key_descriptor, key_privacy);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = get_pub_key_hex_len(key_descriptor,
					     &shared_params->pub_key_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		operation.params[0].memref.parent = &shm;
		operation.params[0].memref.offset = 0;
		operation.params[0].memref.size = shm.size;
	} else if (param0_type == TEEC_MEMREF_TEMP_INPUT) {
		status = set_public_key_buffer(key_descriptor,
					       &operation.params[0],
					       &hex_pub_key);
		if (status != SMW_STATUS_OK)
			goto exit;

		if (SET_OVERFLOW(operation.params[0].tmpref.size,
				 shared_params->pub_key_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	} else {
		shared_params->id = key_identifier->s_id;
	}

	shared_params->key_type = key_type_id;
	shared_params->security_size = key_identifier->security_size;
	shared_params->msg_hashed = sign_attrs->msg_hashed;

	switch (sign_attrs->algo_id) {
	case SMW_CONFIG_SIGN_ALGO_ID_RSA:
		shared_params->sign_algorithm = TEE_ALGORITHM_ID_RSA;
		shared_params->salt_length = sign_attrs->salt_length;
		break;

	case SMW_CONFIG_SIGN_ALGO_ID_EDDSA:
		shared_params->sign_algorithm = TEE_ALGORITHM_ID_EDDSA;
		if (ctx && ctx_length) {
			if (SET_OVERFLOW(ctx_length,
					 shared_params->ctx_length)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}

			SMW_UTILS_MEMCPY(shared_params->ctx, ctx, ctx_length);
		}
		break;

	case SMW_CONFIG_SIGN_ALGO_ID_ECDSA:
		shared_params->sign_algorithm = TEE_ALGORITHM_ID_ECDSA;
		break;

	default:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	operation.paramTypes =
		TEEC_PARAM_TYPES(param0_type, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INPUT, param3_type);

	operation.params[1].tmpref.buffer = shared_params;
	operation.params[1].tmpref.size = shared_params_size;
	operation.params[2].tmpref.buffer = smw_sign_verify_get_msg_buf(args);
	operation.params[2].tmpref.size = smw_sign_verify_get_msg_len(args);
	operation.params[3].tmpref.buffer = smw_sign_verify_get_sign_buf(args);
	operation.params[3].tmpref.size = smw_sign_verify_get_sign_len(args);

	/* Invoke TA */
	status = execute_tee_cmd(cmd_id, &operation);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto exit;

	if (op_id == OPERATION_ID_SIGN) {
		if (!SET_OVERFLOW(operation.params[3].tmpref.size,
				  sign_length)) {
			smw_sign_verify_set_sign_len(args, sign_length);

			if (status != SMW_STATUS_OK)
				goto exit;

			SMW_DBG_PRINTF(DEBUG, "Output (%u):\n", sign_length);
			SMW_DBG_HEX_DUMP(DEBUG,
					 operation.params[3].tmpref.buffer,
					 sign_length, 4);
		} else {
			status = SMW_STATUS_OPERATION_FAILURE;
		}
	}

exit:
	if (shared_params)
		free(shared_params);

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT)
		TEEC_ReleaseSharedMemory(&shm);

	if (key_descriptor &&
	    key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 &&
	    hex_pub_key)
		SMW_UTILS_FREE(hex_pub_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_sign_verify_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_SIGN:
	case OPERATION_ID_VERIFY:
		*status = sign_verify(args, op_id);
		break;
	default:
		return false;
	}

	return true;
}
