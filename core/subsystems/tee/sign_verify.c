// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"
#include "smw_osal.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "tee.h"

#define SIGNATURE_TYPE_ID(_id)                                                 \
	{                                                                      \
		.smw_id = SMW_CONFIG_SIGN_TYPE_ID_##_id,                       \
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
	SIGNATURE_TYPE_ID(DEFAULT),
	SIGNATURE_TYPE_ID(RSASSA_PKCS1_V1_5),
	SIGNATURE_TYPE_ID(RSASSA_PSS),
};

static int tee_convert_signature_type_id(enum smw_config_sign_type_id smw_id,
					 enum tee_signature_type *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i;
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

	struct smw_keymgr_descriptor *key_descriptor = &args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	struct sign_verify_shared_params shared_params = { 0 };

	uint32_t param0_type = TEEC_NONE;
	uint32_t param3_type;

	enum tee_key_type key_type_id;
	enum smw_keymgr_privacy_id key_privacy;

	uint32_t cmd_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	status = tee_convert_key_type(key_identifier->type_id, &key_type_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (key_type_id == TEE_KEY_TYPE_ID_RSA) {
		/*
		 * Signature type is mandatory.
		 * Salt length optional attribute is only for RSASSA-PSS
		 * signature type.
		 */
		if (args->attributes.signature_type ==
		    SMW_CONFIG_SIGN_TYPE_ID_DEFAULT) {
			SMW_DBG_PRINTF(ERROR, "No signature type set\n");
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		} else if (args->attributes.signature_type ==
				   SMW_CONFIG_SIGN_TYPE_ID_RSASSA_PKCS1_V1_5 &&
			   args->attributes.salt_length) {
			SMW_DBG_PRINTF(ERROR,
				       "Salt length not supported for %s\n",
				       RSASSA_PKCS1_V1_5_STR);
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	status = tee_convert_hash_algorithm_id(args->algo_id,
					       &shared_params.hash_algorithm);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = tee_convert_signature_type_id(args->attributes.signature_type,
					       &shared_params.signature_type);
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
			if (key_type_id == TEE_KEY_TYPE_ID_RSA) {
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

	shared_params.pub_key_len =
		smw_keymgr_get_public_length(key_descriptor);

	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT) {
		status = copy_keys_to_shm(&shm, key_descriptor, key_privacy);
		if (status != SMW_STATUS_OK)
			goto exit;

		operation.params[0].memref.parent = &shm;
		operation.params[0].memref.offset = 0;
		operation.params[0].memref.size = shm.size;
	} else if (param0_type == TEEC_MEMREF_TEMP_INPUT) {
		operation.params[0].tmpref.buffer =
			smw_keymgr_get_public_data(key_descriptor);
		operation.params[0].tmpref.size = shared_params.pub_key_len;
	} else {
		shared_params.id = key_identifier->id;
	}

	shared_params.key_type = key_type_id;
	shared_params.security_size = key_identifier->security_size;
	shared_params.salt_length = args->attributes.salt_length;

	operation.paramTypes =
		TEEC_PARAM_TYPES(param0_type, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INPUT, param3_type);

	operation.params[1].tmpref.buffer = &shared_params;
	operation.params[1].tmpref.size = sizeof(shared_params);
	operation.params[2].tmpref.buffer = smw_sign_verify_get_msg_buf(args);
	operation.params[2].tmpref.size = smw_sign_verify_get_msg_len(args);
	operation.params[3].tmpref.buffer = smw_sign_verify_get_sign_buf(args);
	operation.params[3].tmpref.size = smw_sign_verify_get_sign_len(args);

	/* Invoke TA */
	status = execute_tee_cmd(cmd_id, &operation);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (op_id == OPERATION_ID_SIGN) {
		smw_sign_verify_set_sign_len(args,
					     operation.params[3].tmpref.size);

		SMW_DBG_PRINTF(DEBUG, "Output (%zu):\n",
			       operation.params[3].tmpref.size);
		SMW_DBG_HEX_DUMP(DEBUG, operation.params[3].tmpref.buffer,
				 operation.params[3].tmpref.size, 4);
	}

exit:
	if (param0_type == TEEC_MEMREF_PARTIAL_INPUT)
		TEEC_ReleaseSharedMemory(&shm);

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
