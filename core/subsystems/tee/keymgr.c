// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "smw_osal.h"
#include "global.h"
#include "utils.h"
#include "config.h"
#include "keymgr.h"
#include "tee.h"
#include "tee_subsystem.h"
#include "smw_status.h"

#define KEY_ID_MASK UINT32_MAX

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
	  .security_size = 64 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
	  .tee_key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 128 },
	{ .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
	  .tee_key_type = TEE_KEY_TYPE_ID_DES3,
	  .security_size = 192 },
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
 * @key_type: Key type.
 * @security_size: Key security size in bits.
 *
 * Return:
 * SMW_STATUS_OK			- Size is ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Size is not supported.
 */
static int check_key_security_size(enum smw_config_key_type_id key_type,
				   unsigned int security_size)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(smw_tee_key_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (smw_tee_key_info[i].smw_key_type < key_type)
			continue;
		if (smw_tee_key_info[i].smw_key_type > key_type)
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
 * Error code from smw_keymgr_read_attributes().
 */
static int generate_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int attribute_length = 0;
	unsigned long id = 0;
	unsigned char *attribute_list = NULL;
	enum tee_key_type key_type = TEE_KEY_TYPE_ID_INVALID;
	struct smw_keymgr_attributes attributes = { 0 };
	struct smw_keymgr_generate_key_args *key_args =
		(struct smw_keymgr_generate_key_args *)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	/* Convert smw key type to tee key type */
	status = convert_key_type(key_args->key_type_id, &key_type);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Key type not supported\n", __func__);
		goto exit;
	}

	/* Check that key size is supported by optee */
	status = check_key_security_size(key_args->key_type_id,
					 key_args->security_size);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Key size not supported\n", __func__);
		goto exit;
	}

	/* Parse key attributes */
	if (key_args->key_attributes_list) {
		attribute_list = (unsigned char *)key_args->key_attributes_list;
		attribute_length = key_args->key_attributes_list_length;
		status = smw_keymgr_read_attributes(attribute_list,
						    attribute_length,
						    &attributes);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Undefined key attributes\n",
				       __func__);
			goto exit;
		}
	}

	/*
	 * params[0] = Key security size (in bits) and key type
	 * params[1] = Key ID
	 * params[2] = Persistent or not
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	op.params[0].value.a = key_args->security_size;
	op.params[0].value.b = key_type;
	op.params[2].value.a = attributes.persistent_storage;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_GENERATE_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	id = op.params[1].value.a;
	/* Internal TA ID is 32 bits coded */
	id |= (unsigned long)SUBSYSTEM_ID_TEE << 32;

	/* Update key_identifier struct */
	key_args->key_identifier->subsystem_id = SUBSYSTEM_ID_TEE;
	key_args->key_identifier->key_type_id = key_args->key_type_id;
	key_args->key_identifier->security_size = key_args->security_size;
	key_args->key_identifier->is_private = true;
	key_args->key_identifier->id = id;

	SMW_DBG_PRINTF(DEBUG, "%s: Key #%ld is generated\n", __func__,
		       key_args->key_identifier->id);

exit:
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
	uint32_t key_id = 0;
	struct smw_keymgr_delete_key_args *key_args =
		(struct smw_keymgr_delete_key_args *)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	/* params[0] = Key ID */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	/* Key research is done with Key ID */
	key_id = (uint32_t)(key_args->key_identifier->id & KEY_ID_MASK);
	op.params[0].value.a = key_id;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_DELETE_KEY, &op);
	if (status != SMW_STATUS_OK)
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
	else
		SMW_DBG_PRINTF(DEBUG, "%s: Key #%ld is deleted\n", __func__,
			       key_args->key_identifier->id);

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
