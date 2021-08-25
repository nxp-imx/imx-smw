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
#include "smw_status.h"

#define SECURITY_SIZE_RANGE UINT_MAX

/**
 * struct security_size_range - Security size range
 * @min: Minimum key security size in bits.
 * @max: Maximum key security size in bits.
 * @mod: Modulus key security size in bits.
 */
struct security_size_range {
	unsigned int min;
	unsigned int max;
	unsigned int mod;
};

/**
 * struct - Key info
 * @smw_key_type: SMW key type.
 * @tee_key_type: TEE key type.
 * @security_size: Key security size in bits.
 * @security_size_range: Key security size range.
 * @symmetric: Is a symmetric key or not.
 *
 * key_info must be ordered from lowest to highest.
 * Security sizes must be ordered from lowest to highest for one given
 * key type ID.
 * @security_size_range is considered only
 * if @security_size is set to SECURITY_SIZE_RANGE.
 */
static const struct key_info {
	enum smw_config_key_type_id smw_key_type;
	enum tee_key_type tee_key_type;
	unsigned int security_size;
	struct security_size_range security_size_range;
	bool symmetric;
} key_info[] = { { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST,
		   .tee_key_type = TEE_KEY_TYPE_ID_ECDSA,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 192,
			   .max = 256,
			   .mod = 32,
			},
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
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 128,
			   .max = 256,
			   .mod = 64,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES,
		   .tee_key_type = TEE_KEY_TYPE_ID_DES,
		   .security_size = 56,
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DES3,
		   .tee_key_type = TEE_KEY_TYPE_ID_DES3,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 112,
			   .max = 168,
			   .mod = 56,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP,
		   .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_SM4,
		   .tee_key_type = TEE_KEY_TYPE_ID_INVALID },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_MD5,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 64,
			   .max = 512,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_SHA1,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 80,
			   .max = 512,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_SHA224,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 112,
			   .max = 512,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_SHA256,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 192,
			   .max = 1024,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_SHA384,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 256,
			   .max = 1024,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_SHA512,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 256,
			   .max = 1024,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3,
		   .tee_key_type = TEE_KEY_TYPE_ID_HMAC_SM3,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 80,
			   .max = 1024,
			   .mod = 8,
			},
		   .symmetric = true },
		 { .smw_key_type = SMW_CONFIG_KEY_TYPE_ID_RSA,
		   .tee_key_type = TEE_KEY_TYPE_ID_RSA,
		   .security_size = SECURITY_SIZE_RANGE,
		   .security_size_range = {
			   .min = 256,
			   .max = 4096,
			   .mod = 2,
			},
		   .symmetric = false } };

int tee_convert_key_type(enum smw_config_key_type_id smw_key_type,
			 enum tee_key_type *tee_key_type)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_info);
	enum tee_key_type tmp_type = TEE_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (key_info[i].smw_key_type == smw_key_type) {
			tmp_type = key_info[i].tee_key_type;
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
 * check_security_size() - Check security size.
 * @key_info: Pointer to key info structure.
 * @security_size: Key security size in bits.
 *
 * Check if key security size is supported by OPTEE.
 *
 * Return:
 * true if supported.
 * false if not supported.
 */
static bool check_security_size(const struct key_info *key_info,
				unsigned int security_size)
{
	const struct security_size_range *range =
		&key_info->security_size_range;

	if (key_info->security_size == SECURITY_SIZE_RANGE) {
		if (range->min <= security_size &&
		    range->max >= security_size &&
		    !(security_size % range->mod))
			return true;
		return false;
	} else if (key_info->security_size == security_size) {
		return true;
	}

	return false;
}

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
static const struct key_info *
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
			    check_security_size(&key_info[i], security_size))
				return &key_info[i];
		}
	}

	return NULL;
}

/**
 * set_tmpref_buffer() - Set a shared tmpref buffer parameter.
 * @buffer_type: TEEC memory type.
 * @param_idx: Index of the parameter in @op structure.
 * @buffer: Pointer to the buffer.
 * @buffer_len: @buffer length in bytes.
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Invalid index.
 */
static inline int set_tmpref_buffer(unsigned int mem_type,
				    unsigned int param_idx,
				    unsigned char *buffer,
				    unsigned int buffer_len, TEEC_Operation *op)
{
	if (param_idx > (TEE_NUM_PARAMS - 1))
		return SMW_STATUS_INVALID_PARAM;

	SET_TEEC_PARAMS_TYPE(op->paramTypes, mem_type, param_idx);
	op->params[param_idx].tmpref.buffer = buffer;
	op->params[param_idx].tmpref.size = buffer_len;

	return SMW_STATUS_OK;
}

/**
 * free_tmpref_buffer() - Free a shared tmpref buffer parameter.
 * @param_idx: Index of the parameter in @op structure.
 * @op: Pointer to operation structure containing parameter to free.
 *
 * Return:
 * none
 */
static inline void free_tmpref_buffer(unsigned int param_idx,
				      TEEC_Operation *op)
{
	if (param_idx > (TEE_NUM_PARAMS - 1))
		return;

	if (op->params[param_idx].tmpref.buffer)
		SMW_UTILS_FREE(op->params[param_idx].tmpref.buffer);
}

/**
 * update_exported_buffer() - Update exported buffer and/or buffer length.
 * @format_id: Buffer format set by the user.
 * @hex_buffer: HEX buffer returned by the TA.
 * @hex_buffer_len: @hex_buffer length in bytes, rerturned by the TA.
 * @buffer: Pointer to buffer set by the user.
 * @buffer_len: Pointer to @buffer length in bytes to update.
 *
 * If @format_id is BASE64, @hex_buffer in encoded and @buffer is filled with
 * the encoded buffer. @buffer_len is set to BASE64 buffer length.
 * Else, @buffer_len is set to @hex_buffer_len.
 *
 * Return:
 * SMW_STATUS_OK	- Success.
 * Error code from smw_utils_base64_encode().
 */
static int update_exported_buffer(enum smw_keymgr_format_id format_id,
				  unsigned char *hex_buffer,
				  unsigned int hex_buffer_len,
				  unsigned char *buffer,
				  unsigned int *buffer_len)
{
	int status = SMW_STATUS_OPERATION_FAILURE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Encode hex_buffer in BASE64 buffer */
		status = smw_utils_base64_encode(hex_buffer, hex_buffer_len,
						 buffer, buffer_len);
		if (status != SMW_STATUS_OK)
			goto exit;
	} else {
		*buffer_len = hex_buffer_len;
		status = SMW_STATUS_OK;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * export_pub_key() - Export public key.
 * @key_descriptor: Pointer to key descriptor.
 * @op: Pointer to operation structure to update.
 * @pub_key_idx: Index of the public buffer in @op structure.
 * @modulus_idx: Index of the modulus buffer in @op structure.
 *
 * Return:
 * SMW_STATUS_OK	- Success.
 * Error code from update_exported_buffer().
 */
static int export_pub_key(struct smw_keymgr_descriptor *key_descriptor,
			  TEEC_Operation *op, unsigned int pub_key_idx,
			  unsigned int modulus_idx)
{
	int status = SMW_STATUS_OK;
	unsigned char *pub_data;
	unsigned char *modulus;
	unsigned char *hex_pub = op->params[pub_key_idx].tmpref.buffer;
	unsigned char *hex_modulus = op->params[modulus_idx].tmpref.buffer;
	unsigned int pub_data_len;
	unsigned int modulus_len;
	unsigned int hex_pub_len = op->params[pub_key_idx].tmpref.size;
	unsigned int hex_modulus_len = op->params[modulus_idx].tmpref.size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (hex_pub) {
		pub_data = smw_keymgr_get_public_data(key_descriptor);
		pub_data_len = smw_keymgr_get_public_length(key_descriptor);

		status = update_exported_buffer(key_descriptor->format_id,
						hex_pub, hex_pub_len, pub_data,
						&pub_data_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		/* Update key descriptor public length */
		smw_keymgr_set_public_length(key_descriptor, pub_data_len);

		SMW_DBG_PRINTF(DEBUG, "Public key:\n");
		SMW_DBG_HEX_DUMP(DEBUG, pub_data, pub_data_len, 4);
	} else {
		/*
		 * If public buffer is not set, modulus buffer can't be set for
		 * RSA key type. This check is done in smw_generate_key().
		 */
		goto exit;
	}

	if (hex_modulus) {
		modulus = smw_keymgr_get_modulus(key_descriptor);
		modulus_len = smw_keymgr_get_modulus_length(key_descriptor);

		status = update_exported_buffer(key_descriptor->format_id,
						hex_modulus, hex_modulus_len,
						modulus, &modulus_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		/* Update key descriptor modulus length */
		smw_keymgr_set_modulus_length(key_descriptor, modulus_len);

		SMW_DBG_PRINTF(DEBUG, "Modulus:\n");
		SMW_DBG_HEX_DUMP(DEBUG, modulus, modulus_len, 4);
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_hex_exp_buffer() - Set HEX buffer for export key operation.
 * @format_id: Format of the input buffer.
 * @buffer: Pointer to the input buffer.
 * @hex_buffer: Pointer to the HEX buffer to set.
 * @hex_buffer_len: @hex_buffer length.
 *
 * This function is also used by generated key operation when public key needs
 * to be exported.
 * If @format_id is base64, @hex_buffer is allocated in this function and freed
 * at the end of export_key()/generate_key().
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failure.
 */
static int set_hex_exp_buffer(enum smw_keymgr_format_id format_id,
			      unsigned char *buffer, unsigned char **hex_buffer,
			      unsigned int hex_buffer_len)
{
	int status = SMW_STATUS_ALLOC_FAILURE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (format_id == SMW_KEYMGR_FORMAT_ID_HEX) {
		*hex_buffer = buffer;
		status = SMW_STATUS_OK;
		goto exit;
	}

	*hex_buffer = SMW_UTILS_MALLOC(hex_buffer_len);
	if (!*hex_buffer) {
		SMW_DBG_PRINTF(ERROR, "Allocation failure\n");
		goto exit;
	}

	status = SMW_STATUS_OK;
exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_params_gen_key() - Set shared buffers parameters for generate key
 *                        operation.
 * @key_args: Key generation arguments.
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_NO_KEY_BUFFER	- No parameter to set.
 * Error code from set_tmpref_buffer().
 * Error code from smw_keymgr_get_buffers_lengths().
 * Error code from set_hex_exp_buffer().
 */
static int set_params_gen_key(struct smw_keymgr_generate_key_args *key_args,
			      TEEC_Operation *op)
{
	int status = SMW_STATUS_NO_KEY_BUFFER;
	struct smw_keymgr_descriptor *key_descriptor;
	struct smw_keymgr_attributes *key_attrs = &key_args->key_attributes;
	unsigned char *pub_data;
	unsigned char *modulus;
	unsigned char *hex_modulus = NULL;
	unsigned char *hex_pub_data = NULL;
	unsigned int hex_pub_len;
	unsigned int hex_modulus_len;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* RSA public exponent is set by the user */
	if (key_attrs->rsa_pub_exp) {
		status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT,
					   GEN_PUB_EXP_PARAM_IDX,
					   key_attrs->rsa_pub_exp,
					   key_attrs->rsa_pub_exp_len, op);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	key_descriptor = &key_args->key_descriptor;
	pub_data = smw_keymgr_get_public_data(key_descriptor);

	/*
	 * For RSA key type, modulus buffer can't be set without public
	 * buffer (check done in smw_generate_key())
	 */
	if (!pub_data)
		goto exit;

	status = smw_keymgr_get_buffers_lengths(&key_descriptor->identifier,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&hex_pub_len, NULL,
						&hex_modulus_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (key_descriptor->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		/* Update public buffer length with the one set by the user */
		if (key_attrs->rsa_pub_exp)
			hex_pub_len = key_attrs->rsa_pub_exp_len;

		modulus = smw_keymgr_get_modulus(key_descriptor);

		/* Set modulus buffer */
		status = set_hex_exp_buffer(key_descriptor->format_id, modulus,
					    &hex_modulus, hex_modulus_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
					   GEN_MOD_PARAM_IDX, hex_modulus,
					   hex_modulus_len, op);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	/* Set public buffer */
	status = set_hex_exp_buffer(key_descriptor->format_id, pub_data,
				    &hex_pub_data, hex_pub_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
				   GEN_PUB_KEY_PARAM_IDX, hex_pub_data,
				   hex_pub_len, op);

exit:
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
	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_identifier *key_identifier =
		&key_args->key_descriptor.identifier;
	struct smw_keymgr_attributes *key_attrs;
	const struct key_info *key = NULL;
	struct keymgr_shared_params shared_params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	/* Get key info and check key type and key security size */
	key = find_check_key_info(key_identifier->type_id,
				  key_identifier->security_size);
	if (!key) {
		SMW_DBG_PRINTF(ERROR,
			       "%s: Key type or key size not supported\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	key_attrs = &key_args->key_attributes;

	/* Set shared buffers parameters if needed */
	status = set_params_gen_key(key_args, &op);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
		goto exit;

	if (key_attrs->persistent_storage)
		shared_params.persistent_storage =
			key_attrs->persistent_storage;

	shared_params.security_size = key_identifier->security_size;
	shared_params.key_type = key->tee_key_type;
	op.params[0].tmpref.buffer = &shared_params;
	op.params[0].tmpref.size = sizeof(shared_params);

	/*
	 * params[0] = Pointer to generate shared params structure.
	 * params[1] = Pointer to public key buffer or none.
	 * params[2] = Pointer to modulus buffer (RSA) or none.
	 * params[3] = Pointer to public exponent attribute (RSA) or none.
	 */
	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_MEMREF_TEMP_INOUT, 0);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_GENERATE_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	/* Update key_identifier struct */
	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_identifier->subsystem_id = SUBSYSTEM_ID_TEE;
	key_identifier->id = shared_params.id;
	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is generated\n", __func__,
		       key_identifier->id);

	/* For RSA key type attribute is the public exponent length in bytes */
	if (key->tee_key_type == TEE_KEY_TYPE_ID_RSA) {
		if (key_attrs->rsa_pub_exp_len)
			key_identifier->attribute = key_attrs->rsa_pub_exp_len;
		else
			key_identifier->attribute = DEFAULT_RSA_PUB_EXP_LEN;
	}

	/* Export public key if needed */
	status = export_pub_key(&key_args->key_descriptor, &op,
				GEN_PUB_KEY_PARAM_IDX, GEN_MOD_PARAM_IDX);

exit:
	if (key_args &&
	    key_args->key_descriptor.format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Free HEX public data buffer allocated */
		free_tmpref_buffer(GEN_PUB_KEY_PARAM_IDX, &op);

		/* Free HEX modulus buffer allocated */
		free_tmpref_buffer(GEN_MOD_PARAM_IDX, &op);
	}

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

	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is %sdeleted\n", __func__,
		       key_args->key_descriptor.identifier.id,
		       (status == SMW_STATUS_OK) ? "" : "NOT ");

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
	case TEE_KEY_TYPE_ID_HMAC_MD5:
	case TEE_KEY_TYPE_ID_HMAC_SHA1:
	case TEE_KEY_TYPE_ID_HMAC_SHA224:
	case TEE_KEY_TYPE_ID_HMAC_SHA256:
	case TEE_KEY_TYPE_ID_HMAC_SHA384:
	case TEE_KEY_TYPE_ID_HMAC_SHA512:
	case TEE_KEY_TYPE_ID_HMAC_SM3:
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
	case TEE_KEY_TYPE_ID_RSA:
		/*
		 * OPTEE does not support import of private key only for
		 * asymmetric key type.
		 * For RSA key type, modulus presence is already check in
		 * core/keymgr.c file.
		 */
		if (!pub_data) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: Asymmetric public buffer not set\n",
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
 * OPTEE secure subsystem only exports asymmetric public key.
 *
 * Return:
 * SMW_STATUS_OK			- Configuration ok.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Configuration not supported.
 */
static int check_export_key_config(struct smw_keymgr_descriptor *key_descriptor)
{
	switch (key_descriptor->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		/*
		 * For RSA key type, modulus presence is already check in
		 * core/keymgr.c file
		 */
		if (smw_keymgr_get_private_data(key_descriptor) ||
		    !smw_keymgr_get_public_data(key_descriptor)) {
			SMW_DBG_PRINTF(ERROR,
				       "%s: OPTEE only exports public key\n",
				       __func__);
			return SMW_STATUS_OPERATION_NOT_SUPPORTED;
		}
		break;

	default:
		SMW_DBG_PRINTF(ERROR,
			       "%s: OPTEE only exports asymmetric public key\n",
			       __func__);
		return SMW_STATUS_OPERATION_NOT_SUPPORTED;
	}

	return SMW_STATUS_OK;
}

/**
 * set_hex_imp_buffer() - Set HEX buffer for import key operation.
 * @format_id: Format of the input buffer.
 * @buffer: Pointer to the input buffer.
 * @buffer_len: @buffer length in bytes.
 * @hex_buffer: Pointer to the HEX buffer to update.
 * @hex_buffer_len: Pointer @hex_buffer length to update.
 *
 * If format id is BASE64, the input buffer in converted in HEX format. In this
 * case @hex_buffer is allocated in smw_utils_base64_decode() and will be freed
 * at the end of import_key().
 *
 * Return:
 * SMW_STATUS_OK	- Success.
 * Error code from smw_utils_base64_decode().
 */
static int set_hex_imp_buffer(enum smw_keymgr_format_id format_id,
			      unsigned char *buffer, unsigned int buffer_len,
			      unsigned char **hex_buffer,
			      unsigned int *hex_buffer_len)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Convert buffer in hex format */
		status = smw_utils_base64_decode(buffer, buffer_len, hex_buffer,
						 hex_buffer_len);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Failed to decode base64\n",
				       __func__);
			goto exit;
		}
	} else {
		*hex_buffer = buffer;
		*hex_buffer_len = buffer_len;
		status = SMW_STATUS_OK;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_params_import_pub_key() - Set public key buffer shared parameter for
 *                               import operation.
 * @key_descriptor: Pointer to key descriptor.
 * @key: Pointer to key info.
 * @key_size_bytes: Key size in bytes.
 * @pub_data: Pointer to public buffer set by the user.
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Private key buffer length invalid.
 * Error code from set_hex_imp_buffer().
 * Error code from set_tmpref_buffer().
 */
static int
set_params_import_pub_key(struct smw_keymgr_descriptor *key_descriptor,
			  const struct key_info *key,
			  unsigned int key_size_bytes, unsigned char *pub_data,
			  TEEC_Operation *op)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned char *hex_pub_data;
	unsigned int hex_pub_len;
	unsigned int pub_data_len =
		smw_keymgr_get_public_length(key_descriptor);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (key->symmetric) {
		SMW_DBG_PRINTF(ERROR, "%s: Public key set for symmetric key\n",
			       __func__);
		goto exit;
	}

	status = set_hex_imp_buffer(key_descriptor->format_id, pub_data,
				    pub_data_len, &hex_pub_data, &hex_pub_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * Check coherence between buffer length and security size for
	 * ECDSA public key
	 */
	if (key->tee_key_type == TEE_KEY_TYPE_ID_ECDSA &&
	    (hex_pub_len != 2 * key_size_bytes)) {
		SMW_DBG_PRINTF(ERROR, "%s: Wrong public key buffer length\n",
			       __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	status =
		set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT, IMP_PUB_KEY_PARAM_IDX,
				  hex_pub_data, hex_pub_len, op);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_params_import_priv_key() - Set private key buffer shared parameter for
 *                                import operation.
 * @key_type: TEE key type.
 * @key_descriptor: Pointer to key descriptor.
 * @key_size_bytes: Key size in bytes.
 * @priv_data: Pointer to private buffer set by the user.
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Private key buffer length invalid.
 * Error code from set_hex_imp_buffer().
 * Error code from set_tmpref_buffer().
 */
static int
set_params_import_priv_key(enum tee_key_type key_type,
			   struct smw_keymgr_descriptor *key_descriptor,
			   unsigned int key_size_bytes,
			   unsigned char *priv_data, TEEC_Operation *op)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned char *hex_priv_data;
	unsigned int hex_priv_len;
	unsigned int priv_data_len =
		smw_keymgr_get_private_length(key_descriptor);

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = set_hex_imp_buffer(key_descriptor->format_id, priv_data,
				    priv_data_len, &hex_priv_data,
				    &hex_priv_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Check coherence between buffer length and security size */
	if ((key_type != TEE_KEY_TYPE_ID_RSA &&
	     hex_priv_len != key_size_bytes) ||
	    (key_type == TEE_KEY_TYPE_ID_RSA &&
	     hex_priv_len > key_size_bytes)) {
		SMW_DBG_PRINTF(ERROR, "%s: Wrong private key buffer length\n",
			       __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT,
				   IMP_PRIV_KEY_PARAM_IDX, hex_priv_data,
				   hex_priv_len, op);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_params_import_modulus() - Set modulus buffer shared parameter for import
 *                               operation.
 * @key_descriptor: Pointer to key descriptor.
 * @key_size_bytes: Key size in bytes.
 * @modulus: Pointer to modulus buffer set by the user.
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Modulus buffer length invalid.
 * Error code from set_hex_imp_buffer().
 * Error code from set_tmpref_buffer().
 */
static int
set_params_import_modulus(struct smw_keymgr_descriptor *key_descriptor,
			  unsigned int key_size_bytes, unsigned char *modulus,
			  TEEC_Operation *op)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned char *hex_modulus;
	unsigned int hex_modulus_len;
	unsigned int modulus_len =
		smw_keymgr_get_modulus_length(key_descriptor);

	SMW_DBG_TRACE_FUNCTION_CALL;

	status =
		set_hex_imp_buffer(key_descriptor->format_id, modulus,
				   modulus_len, &hex_modulus, &hex_modulus_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Check coherence between buffer length and security size */
	if (hex_modulus_len != key_size_bytes) {
		SMW_DBG_PRINTF(ERROR, "%s: Wrong modulus buffer length\n",
			       __func__);
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_INPUT, IMP_MOD_PARAM_IDX,
				   hex_modulus, hex_modulus_len, op);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_params_import_key() - Set and check buffers parameters.
 * @key_descriptor: Pointer to key descriptor.
 * @key: Pointer to key info.
 * @key_size_bytes: Key size in bytes.
 * @op: Pointer to TEEC Operation structure to update.
 *
 * This function checks the presence of key buffers and set buffers shared
 * with the TA.
 *
 * Return:
 * SMW_STATUS_OK	- Success.
 * Error code from check_import_key_buffers_presence().
 * Error code from set_params_import_pub_key().
 * Error code from set_params_import_priv_key().
 * Error code from set_params_import_modulus().
 */
static int set_params_import_key(struct smw_keymgr_descriptor *key_descriptor,
				 const struct key_info *key,
				 unsigned int key_size_bytes,
				 TEEC_Operation *op)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned char *public_data = smw_keymgr_get_public_data(key_descriptor);
	unsigned char *private_data =
		smw_keymgr_get_private_data(key_descriptor);
	unsigned char *modulus = smw_keymgr_get_modulus(key_descriptor);

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_import_key_buffers_presence(key->tee_key_type,
						   private_data, public_data);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (public_data) {
		status = set_params_import_pub_key(key_descriptor, key,
						   key_size_bytes, public_data,
						   op);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	if (private_data) {
		status = set_params_import_priv_key(key->tee_key_type,
						    key_descriptor,
						    key_size_bytes,
						    private_data, op);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	if (modulus)
		status = set_params_import_modulus(key_descriptor,
						   key_size_bytes, modulus, op);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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
	unsigned int key_size_bytes = 0;
	struct smw_keymgr_import_key_args *key_args = args;
	struct smw_keymgr_identifier *key_identifier = NULL;
	const struct key_info *key = NULL;
	struct keymgr_shared_params shared_params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_identifier = &key_args->key_descriptor.identifier;

	/* Get key info and check key type and key security size */
	key = find_check_key_info(key_identifier->type_id,
				  key_identifier->security_size);
	if (!key) {
		SMW_DBG_PRINTF(ERROR,
			       "%s: Key type or key size not supported\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	key_size_bytes = BITS_TO_BYTES_SIZE(key_identifier->security_size);
	/* DES and DES3 key buffer must include parity bits */
	if (key->tee_key_type == TEE_KEY_TYPE_ID_DES)
		/* 8 bits of parity for 56bits security size DES key */
		key_size_bytes++;
	else if (key->tee_key_type == TEE_KEY_TYPE_ID_DES3 &&
		 key_identifier->security_size == 112)
		/* 16 bits of parity for 112bits security size DES3 key */
		key_size_bytes += 2;
	else if (key->tee_key_type == TEE_KEY_TYPE_ID_DES3 &&
		 key_identifier->security_size == 168)
		/* 24 bits of parity for 168bits security size DES3 key */
		key_size_bytes += 3;

	/* Set shared buffers parameters */
	status = set_params_import_key(&key_args->key_descriptor, key,
				       key_size_bytes, &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	shared_params.security_size = key_identifier->security_size;
	shared_params.key_type = key->tee_key_type;
	shared_params.persistent_storage =
		key_args->key_attributes.persistent_storage;

	/*
	 * params[0]: Pointer to import shared params structure.
	 * params[1]: Private key buffer or none.
	 * params[2]: Public key buffer or none.
	 * params[3]: Modulus buffer (RSA) or none.
	 */
	op.params[0].tmpref.buffer = &shared_params;
	op.params[0].tmpref.size = sizeof(shared_params);

	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_MEMREF_TEMP_INOUT, 0);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_IMPORT_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	/* Update key_identifier struct */
	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_identifier->subsystem_id = SUBSYSTEM_ID_TEE;
	key_identifier->id = shared_params.id;
	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is imported\n", __func__,
		       key_identifier->id);

	/* For RSA key type attribute is the public exponent length in bytes */
	if (key_identifier->type_id == SMW_CONFIG_KEY_TYPE_ID_RSA)
		key_identifier->attribute =
			op.params[IMP_PUB_KEY_PARAM_IDX].tmpref.size;

exit:
	if (key_args &&
	    key_args->key_descriptor.format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Free HEX private data buffer allocated */
		free_tmpref_buffer(IMP_PRIV_KEY_PARAM_IDX, &op);

		/* Free HEX public data buffer allocated */
		free_tmpref_buffer(IMP_PUB_KEY_PARAM_IDX, &op);

		/* Free HEX modulus buffer allocated */
		free_tmpref_buffer(IMP_MOD_PARAM_IDX, &op);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * export_key() - Export a key from OPTEE storage.
 * @args: Export key parameters.
 *
 * Only ECDSA NIST and RSA public key can be exported.
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
	unsigned int hex_modulus_len = 0;
	unsigned char *hex_pub = NULL;
	unsigned char *pub_data = NULL;
	unsigned char *modulus = NULL;
	unsigned char *hex_modulus = NULL;
	struct smw_keymgr_export_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_descriptor = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_descriptor = &key_args->key_descriptor;

	status = check_export_key_config(key_descriptor);
	if (status != SMW_STATUS_OK)
		goto exit;

	pub_data = smw_keymgr_get_public_data(key_descriptor);
	modulus = smw_keymgr_get_modulus(key_descriptor);

	/* Get public key buffer length for HEX format */
	status = smw_keymgr_get_buffers_lengths(&key_descriptor->identifier,
						SMW_KEYMGR_FORMAT_ID_HEX,
						&hex_pub_len, NULL,
						&hex_modulus_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Set public HEX buffer */
	status = set_hex_exp_buffer(key_descriptor->format_id, pub_data,
				    &hex_pub, hex_pub_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Set modulus HEX buffer */
	if (key_descriptor->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA &&
	    modulus) {
		status = set_hex_exp_buffer(key_descriptor->format_id, modulus,
					    &hex_modulus, hex_modulus_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
					   EXP_MOD_PARAM_IDX, hex_modulus,
					   hex_modulus_len, &op);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	/*
	 * params[0] = TEE Key ID, Key security size.
	 * params[1] = Public key buffer.
	 * params[2] = Modulus buffer (RSA key) or none.
	 * params[3] = None.
	 */
	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_VALUE_INPUT, 0);
	op.params[0].value.a = key_descriptor->identifier.id;
	op.params[0].value.b = key_descriptor->identifier.security_size;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT,
				   EXP_PUB_KEY_PARAM_IDX, hex_pub, hex_pub_len,
				   &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_EXPORT_KEY, &op);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	/* Export public key */
	status = export_pub_key(key_descriptor, &op, EXP_PUB_KEY_PARAM_IDX,
				EXP_MOD_PARAM_IDX);

exit:
	if (key_descriptor &&
	    key_descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Free HEX public data buffer allocated */
		free_tmpref_buffer(EXP_PUB_KEY_PARAM_IDX, &op);

		/* Free HEX modulus buffer allocated */
		free_tmpref_buffer(EXP_MOD_PARAM_IDX, &op);
	}

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
