// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "smw_osal.h"
#include "utils.h"
#include "base64.h"
#include "config.h"
#include "keymgr.h"
#include "tee.h"
#include "tee_subsystem.h"
#include "smw_status.h"

/**
 * struct - Key info
 * @smw_key_type: SMW key type.
 * @tee_key_type: TEE key type.
 * @security_size: Key security size in bits.
 *
 * smw_tee_key_info must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest for one given
 * key type ID.
 */
static struct {
	enum smw_config_key_type_id smw_key_type;
	enum tee_key_type tee_key_type;
	unsigned int security_size;
} smw_tee_key_info[] = {
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 192 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 224 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 256 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 384 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
	  .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
	  .security_size = 521 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
	  .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
	  .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .tee_key_type = TEE_KEY_TYPE_ID_AES,
	  .security_size = 128 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .tee_key_type = TEE_KEY_TYPE_ID_AES,
	  .security_size = 192 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
	  .tee_key_type = TEE_KEY_TYPE_ID_AES,
	  .security_size = 256 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES,
	  .tee_key_type = TEE_KEY_TYPE_ID_DES,
	  .security_size = 56 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
	  .tee_key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 112 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
	  .tee_key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 168 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP,
	  .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_SM4,
	  .tee_key_type = TEE_KEY_TYPE_ID_INVALID }
};

/**
 * convert_key_type() - Convert SMW key type to TEE key type.
 * @smw_key_type: SMW key type.
 * @tee_key_type: TEE key type. Not updated if conversion can't be done.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Invalid key type.
 */
static int convert_key_type(enum smw_config_key_type_id smw_key_type,
			    enum tee_key_type *tee_key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(smw_tee_key_info);
	enum tee_key_type tmp_type = TEE_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (smw_tee_key_info[i].smw_key_type == smw_key_type) {
			tmp_type = smw_tee_key_info[i].tee_key_type;
			if (tmp_type != TEE_KEY_TYPE_ID_INVALID) {
				*tee_key_type = tmp_type;
				status = SMW_STATUS_OK;
			}
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_key_security_size() - Check key security size value.
 * @key_type_id: Key type ID.
 * @security_size: Key security size in bits.
 *
 * Return:
 * SMW_STATUS_OK			- Size is ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Size is not supported.
 */
static int check_key_security_size(enum smw_config_key_type_id key_type_id,
				   unsigned int security_size)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(smw_tee_key_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (smw_tee_key_info[i].smw_key_type < key_type_id)
			continue;
		if (smw_tee_key_info[i].smw_key_type > key_type_id)
			break;
		if (smw_tee_key_info[i].security_size < security_size)
			continue;
		if (smw_tee_key_info[i].security_size > security_size)
			break;

		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * generate_key() - Generate a key.
 * @args: Key generation arguments.
 *
 * The generated key is stored in tee subsystem storage. It can be transient or
 * persistent object.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int generate_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	enum tee_key_type key_type = TEE_KEY_TYPE_ID_INVALID;
	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	enum smw_keymgr_format_id format_id = key_descriptor->format_id;
	enum smw_config_key_type_id key_type_id = key_identifier->type_id;
	unsigned int security_size = key_identifier->security_size;
	unsigned char *public_data = smw_keymgr_get_public_data(key_descriptor);
	unsigned char *out_key = NULL;
	unsigned int out_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	if (public_data) {
		status =
			smw_keymgr_get_buffers_lengths(key_type_id,
						       security_size,
						       SMW_KEYMGR_FORMAT_ID_HEX,
						       &out_size, NULL);
		if (status != SMW_STATUS_OK)
			goto exit;

		if (format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
			out_key = public_data;
		} else {
			out_key = SMW_UTILS_MALLOC(out_size);
			if (!out_key) {
				SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
				status = SMW_STATUS_ALLOC_FAILURE;
				goto exit;
			}
		}
	}

	/* Convert smw key type to tee key type */
	status = convert_key_type(key_type_id, &key_type);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Key type not supported\n", __func__);
		goto exit;
	}

	/* Check that key size is supported by optee */
	status = check_key_security_size(key_type_id, security_size);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Key size not supported\n", __func__);
		goto exit;
	}

	/*
	 * params[0] = Key security size (in bits) and key type
	 * params[1] = Key ID
	 * params[2] = Persistent or not
	 * params[3] = Key buffer or none
	 */
	if (out_key) {
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_MEM_OUTPUT);
		op.params[3].tmpref.buffer = out_key;
		op.params[3].tmpref.size = out_size;
	} else {
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	}

	op.params[0].value.a = security_size;
	op.params[0].value.b = key_type;
	op.params[2].value.a = key_args->key_attributes.persistent_storage;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_GENERATE_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	/* Update key_identifier struct */
	status = smw_keymgr_get_privacy_id(key_type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_identifier->subsystem_id = SUBSYSTEM_ID_TEE;
	key_identifier->id = op.params[1].value.a;
	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is generated\n", __func__,
		       key_identifier->id);

	if (out_key) {
		if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			status =
				smw_utils_base64_encode(out_key, out_size,
							public_data, &out_size);
			if (status != SMW_STATUS_OK)
				goto exit;
		}

		SMW_DBG_PRINTF(DEBUG, "Out key:\n");
		SMW_DBG_HEX_DUMP(DEBUG, public_data, out_size, 4);
	}

	smw_keymgr_set_public_length(key_descriptor, out_size);

exit:
	if (out_key && out_key != public_data)
		SMW_UTILS_FREE(out_key);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * delete_key() - Delete a key present in TEE subsystem storage.
 * @args: Key deletion arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int delete_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_delete_key_args *key_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	/* params[0] = Key ID */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	/* Key research is done with Key ID */
	op.params[0].value.a = key_args->key_descriptor.identifier.id;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_DELETE_KEY, &op);
	if (status != SMW_STATUS_OK)
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
	else
		SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is deleted\n", __func__,
			       key_args->key_descriptor.identifier.id);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_key_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_GENERATE_KEY:
		*status = generate_key(args);
		break;
	case OPERATION_ID_DELETE_KEY:
		*status = delete_key(args);
		break;
	case OPERATION_ID_DERIVE_KEY:
		*status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
		break;
	case OPERATION_ID_UPDATE_KEY:
		*status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
		break;
	case OPERATION_ID_IMPORT_KEY:
		*status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = SMW_STATUS_OPERATION_NOT_CONFIGURED;
		break;
	default:
		return false;
	}

	return true;
}
