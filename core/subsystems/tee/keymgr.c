// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
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
 * @symmetric: Is a symmetric key or not.
 *
 * key_info must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest for one given
 * key type ID.
 */
static struct key_info {
	enum smw_config_key_type_id smw_key_type;
	enum tee_key_type tee_key_type;
	unsigned int security_size;
	bool symmetric;
} key_info[] = { { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		   .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 192,
		   .symmetric = false },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		   .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 224,
		   .symmetric = false },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		   .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 256,
		   .symmetric = false },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		   .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 384,
		   .symmetric = false },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		   .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = 521,
		   .symmetric = false },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1,
		   .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1,
		   .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
		   .tee_key_type = TEE_KEY_TYPE_ID_AES,
		   .security_size = 128,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
		   .tee_key_type = TEE_KEY_TYPE_ID_AES,
		   .security_size = 192,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_AES,
		   .tee_key_type = TEE_KEY_TYPE_ID_AES,
		   .security_size = 256,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES,
		   .tee_key_type = TEE_KEY_TYPE_ID_DES,
		   .security_size = 56,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
		   .tee_key_type = TEE_KEY_TYPE_ID_DES3,
		   .security_size = 112,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
		   .tee_key_type = TEE_KEY_TYPE_ID_DES3,
		   .security_size = 168,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP,
		   .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_SM4,
		   .tee_key_type = TEE_KEY_TYPE_ID_INVALID } };

/**
 * find_check_key_info() - Get and check key info.
 * @key_type_id: Key type ID.
 * @security_size: Key security size in bits.
 *
 * Check if key type and key security size are supported by OPTEE.
 *
 * Return:
 * Pointer to key info.
 * NULL if not supported.
 */
static struct key_info *
find_check_key_info(enum smw_config_key_type_id key_type_id,
		    unsigned int security_size)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (key_info[i].smw_key_type == key_type_id) {
			if (key_info[i].tee_key_type !=
				    TEE_KEY_TYPE_ID_INVALID &&
			    key_info[i].security_size == security_size)
				return &key_info[i];
		}
	}

	return NULL;
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
	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&key_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;
	struct key_info *key = NULL;
	enum smw_keymgr_format_id format_id = key_descriptor->format_id;
	enum smw_config_key_type_id key_type_id = key_identifier->type_id;
	unsigned int security_size = key_identifier->security_size;
	unsigned char *public_data = smw_keymgr_get_public_data(key_descriptor);
	unsigned char *out_key = NULL;
	unsigned int out_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	/* Get key info and check key type and key security size */
	key = find_check_key_info(key_type_id, security_size);
	if (!key) {
		SMW_DBG_PRINTF(ERROR,
			       "%s: Key type or key size not supported\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

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

	/*
	 * params[0] = Key security size (in bits) and key type
	 * params[1] = Key ID
	 * params[2] = Persistent or not
	 * params[3] = Key buffer or none
	 */
	if (out_key) {
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT);
		op.params[3].tmpref.buffer = out_key;
		op.params[3].tmpref.size = out_size;
	} else {
		op.paramTypes =
			TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);
	}

	op.params[0].value.a = security_size;
	op.params[0].value.b = key->tee_key_type;
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

/**
 * check_import_key_buffers_presence() - Check if buffers are correctly set.
 * @key_type: Key type of the key to import.
 * @priv_data: Pointer to private key buffer.
 * @pub_data: Pointer to public key buffer.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_INVALID_PARAM		- One of the parameters if invalid.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation not supported by subsystem.
 */
static int check_import_key_buffers_presence(enum tee_key_type key_type,
					     unsigned char *priv_data,
					     unsigned char *pub_data)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (key_type) {
	case TEE_KEY_TYPE_ID_AES:
	case TEE_KEY_TYPE_ID_DES:
	case TEE_KEY_TYPE_ID_DES3:
		/* Symmetric key cases */
		if (!priv_data) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Symmetric private key is not set\n",
				       __func__);
			return SMW_STATUS_INVALID_PARAM;
		}

		if (pub_data) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Symmetric public key is set\n",
				       __func__);
			return SMW_STATUS_INVALID_PARAM;
		}

		break;

	case TEE_KEY_TYPE_ID_ECDSA:
		/*
		 * OPTEE does not support import of private key only for
		 * ECDSA key type
		 */
		if (!pub_data) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Can't import ECDSA private key\n",
				       __func__);
			return SMW_STATUS_OPERATION_NOT_SUPPORTED;
		}

		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	return SMW_STATUS_OK;
}

/**
 * check_export_key_config() - Check key descriptor configuration.
 * @key_descriptor: Pointer to key descriptor.
 *
 * OPTEE secure subsystem only exports ECDSA NIST public key.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Configuration not supported.
 */
static int check_export_key_config(struct smw_keymgr_descriptor *key_descriptor)
{
	if (key_descriptor->identifier.type_id !=
	    SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST) {
		SMW_DBG_PRINTF(ERROR,
			       "%s: OPTEE only exports ECDSA NIST public key\n",
			       __func__);
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;
	}

	if (smw_keymgr_get_private_data(key_descriptor) ||
	    !smw_keymgr_get_public_data(key_descriptor)) {
		SMW_DBG_PRINTF(ERROR, "%s: OPTEE only exports public key\n",
			       __func__);
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;
	}

	return SMW_STATUS_OK;
}

/**
 * import_key() - Import a key or keypair in OPTEE OS storage.
 * @args: Import key parameters.
 *
 * A symmetric key, an asymmetric public key or an asymmetric keypair
 * can be imported.
 * Key must be plain text.
 * Key format can be "HEX" or "BASE64". In case of "BASE64" format, key is
 * decoded prior to call the TA key import service.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation parameters not supported.
 * SMW_STATUS_INVALID_PARAM		- One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE		- Memory allocation failed.
 * SMW_STATUS_OPERATION_FAILURE		- Operation failed.
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Trusted application failed.
 */
static int import_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int hex_priv_len = 0;
	unsigned int hex_pub_len = 0;
	unsigned int key_size_bytes = 0;
	unsigned int priv_data_len = 0;
	unsigned int pub_data_len = 0;
	unsigned int security_size = 0;
	unsigned int param_priv = TEEC_NONE;
	unsigned int param_pub = TEEC_NONE;
	unsigned char *hex_pub = NULL;
	unsigned char *hex_priv = NULL;
	unsigned char *priv_data = NULL;
	unsigned char *pub_data = NULL;
	struct smw_keymgr_import_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_descriptor = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct key_info *key = NULL;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_descriptor = &key_args->key_descriptor;
	key_identifier = &key_descriptor->identifier;
	key_type_id = key_identifier->type_id;
	security_size = key_identifier->security_size;

	/* Get key info and check key type and key security size */
	key = find_check_key_info(key_type_id, security_size);
	if (!key) {
		SMW_DBG_PRINTF(ERROR,
			       "%s: Key type or key size not supported\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	priv_data = smw_keymgr_get_private_data(key_descriptor);
	pub_data = smw_keymgr_get_public_data(key_descriptor);

	status = check_import_key_buffers_presence(key->tee_key_type, priv_data,
						   pub_data);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_size_bytes = BITS_TO_BYTES_SIZE(security_size);
	/* DES and DES3 key buffer must include parity bits */
	if (key->tee_key_type == TEE_KEY_TYPE_ID_DES)
		/* 8 bits of parity for 56bits security size DES key */
		key_size_bytes++;
	else if (key->tee_key_type == TEE_KEY_TYPE_ID_DES3 &&
		 security_size == 112)
		/* 16 bits of parity for 112bits security size DES3 key */
		key_size_bytes += 2;
	else if (key->tee_key_type == TEE_KEY_TYPE_ID_DES3 &&
		 security_size == 168)
		/* 24 bits of parity for 168bits security size DES3 key */
		key_size_bytes += 3;

	if (pub_data) {
		if (key->symmetric) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Public key set for symmetric key\n",
				       __func__);
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}

		pub_data_len = smw_keymgr_get_public_length(key_descriptor);

		if (key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			status =
				smw_utils_base64_decode(pub_data, pub_data_len,
							&hex_pub, &hex_pub_len);
			if (status != SMW_STATUS_OK) {
				SMW_DBG_PRINTF(ERROR,
					       "%s: Failed to decode base64\n",
					       __func__);
				goto exit;
			}
		} else {
			hex_pub = pub_data;
			hex_pub_len = pub_data_len;
		}

		/* Check coherence between buffer length and security size */
		if (hex_pub_len != 2 * key_size_bytes) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Wrong public key buffer length\n",
				       __func__);
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	if (priv_data) {
		priv_data_len = smw_keymgr_get_private_length(key_descriptor);

		if (key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			/* Convert buffer in hex format */
			status = smw_utils_base64_decode(priv_data,
							 priv_data_len,
							 &hex_priv,
							 &hex_priv_len);
			if (status != SMW_STATUS_OK) {
				SMW_DBG_PRINTF(ERROR,
					       "%s: Failed to decode base64\n",
					       __func__);
				goto exit;
			}
		} else {
			hex_priv = priv_data;
			hex_priv_len = priv_data_len;
		}

		/* Check coherence between buffer length and security size */
		if (hex_priv_len != key_size_bytes) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Wrong private key buffer length\n",
				       __func__);
			status = SMW_STATUS_INVALID_PARAM;
			goto exit;
		}
	}

	/*
	 * params[0]: Key security size and key type.
	 * params[1]: Persistent, new Key ID imported.
	 * params[2]: Private key buffer if set.
	 * params[3]: Public key buffer if set.
	 */
	op.params[0].value.a = security_size;
	op.params[0].value.b = key->tee_key_type;
	op.params[1].value.a = key_args->key_attributes.persistent_storage;
	op.params[2].tmpref.buffer = hex_priv;
	op.params[2].tmpref.size = hex_priv_len;
	op.params[3].tmpref.buffer = hex_pub;
	op.params[3].tmpref.size = hex_pub_len;

	if (hex_priv)
		param_priv = TEEC_MEMREF_TEMP_INPUT;

	if (hex_pub)
		param_pub = TEEC_MEMREF_TEMP_INPUT;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INOUT,
					 param_priv, param_pub);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_IMPORT_KEY, &op);
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
	key_identifier->id = op.params[1].value.b;
	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is imported\n", __func__,
		       key_identifier->id);

exit:
	if (key_descriptor &&
	    key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		if (hex_priv)
			free(hex_priv);

		if (hex_pub)
			free(hex_pub);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * export_key() - Export a key from OPTEE storage.
 * @args: Export key parameters.
 *
 * Only ECDSA NIST public key can be exported.
 *
 * Return:
 * SMW_STATUS_OK			- Success.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation parameters not supported.
 * SMW_STATUS_INVALID_PARAM		- One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE		- Memory allocation failed.
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Trusted application failed.
 */
static int export_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int hex_pub_len = 0;
	unsigned int security_size = 0;
	unsigned int pub_data_len = 0;
	unsigned char *hex_pub = NULL;
	unsigned char *pub_data = NULL;
	struct smw_keymgr_export_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_descriptor = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	enum smw_keymgr_format_id format_id = SMW_KEYMGR_FORMAT_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_descriptor = &key_args->key_descriptor;

	status = check_export_key_config(key_descriptor);
	if (status != SMW_STATUS_OK)
		goto exit;

	pub_data = smw_keymgr_get_public_data(key_descriptor);
	key_identifier = &key_descriptor->identifier;
	key_type_id = key_identifier->type_id;
	security_size = key_identifier->security_size;

	/* Get public key buffer length for HEX format */
	status = smw_keymgr_get_buffers_lengths(key_type_id, security_size,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&hex_pub_len, NULL);
	if (status != SMW_STATUS_OK)
		goto exit;

	format_id = key_descriptor->format_id;

	if (format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
		hex_pub = pub_data;
	} else {
		hex_pub = SMW_UTILS_MALLOC(hex_pub_len);
		if (!hex_pub) {
			SMW_DBG_PRINTF(ERROR, "%s: Allocation failure\n",
				       __func__);
			status = SMW_STATUS_ALLOC_FAILURE;
			goto exit;
		}
	}

	/*
	 * params[0] = TEE Key ID, Key security size.
	 * params[1] = Key buffer.
	 * params[2] = None.
	 * params[3] = None.
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = key_identifier->id;
	op.params[0].value.b = security_size;
	op.params[1].tmpref.buffer = hex_pub;
	op.params[1].tmpref.size = hex_pub_len;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_EXPORT_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	/* Get public key buffer length address */
	pub_data_len = smw_keymgr_get_public_length(key_descriptor);

	/* Encode key in base64 format */
	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		status = smw_utils_base64_encode(hex_pub, hex_pub_len, pub_data,
						 &pub_data_len);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	SMW_DBG_PRINTF(DEBUG, "Out key:\n");
	SMW_DBG_HEX_DUMP(DEBUG, pub_data, pub_data_len, 4);

exit:
	if (hex_pub && hex_pub != pub_data)
		SMW_UTILS_FREE(hex_pub);

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
		*status = import_key(args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(args);
		break;
	default:
		return false;
	}

	return true;
}
