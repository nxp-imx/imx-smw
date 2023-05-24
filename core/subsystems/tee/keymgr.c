// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "tlv.h"
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

/**
 * struct - Key usage
 * @usage_str: SMW usage.
 * @tee_usage: TEE key usage.
 */
static const struct {
	const char *usage_str;
	unsigned int tee_usage;
} key_usage[] = {
	{ .usage_str = EXPORT_STR, .tee_usage = TEE_KEY_USAGE_EXPORTABLE },
	{ .usage_str = COPY_STR, .tee_usage = TEE_KEY_USAGE_COPYABLE },
	{ .usage_str = ENCRYPT_STR, .tee_usage = TEE_KEY_USAGE_ENCRYPT },
	{ .usage_str = DECRYPT_STR, .tee_usage = TEE_KEY_USAGE_DECRYPT },
	{ .usage_str = SIGN_MESSAGE_STR,
	  .tee_usage = TEE_KEY_USAGE_SIGN | TEE_KEY_USAGE_MAC },
	{ .usage_str = VERIFY_MESSAGE_STR,
	  .tee_usage = TEE_KEY_USAGE_VERIFY | TEE_KEY_USAGE_MAC },
	{ .usage_str = SIGN_HASH_STR, .tee_usage = TEE_KEY_USAGE_SIGN },
	{ .usage_str = VERIFY_HASH_STR, .tee_usage = TEE_KEY_USAGE_VERIFY },
	{ .usage_str = DERIVE_STR, .tee_usage = TEE_KEY_USAGE_DERIVE }
};

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

static enum smw_config_key_type_id
key_type_tee_to_smw(enum tee_key_type tee_key_type)
{
	enum smw_config_key_type_id ret_type = SMW_CONFIG_KEY_TYPE_ID_INVALID;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(key_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (key_info[i].tee_key_type == tee_key_type) {
			SMW_DBG_PRINTF(DEBUG, "Key type: %d\n", ret_type);
			ret_type = key_info[i].smw_key_type;
			break;
		}
	}

	return ret_type;
}

static bool key_usage_to_value(const char *value, unsigned int *usage)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(key_usage); i++) {
		if (!SMW_UTILS_STRCMP(key_usage[i].usage_str, value)) {
			SMW_DBG_PRINTF(DEBUG, "Key usage: %s\n", value);
			*usage |= key_usage[i].tee_usage;
			return true;
		}
	}

	return false;
}

static int tee_set_key_usage(unsigned char *policy, unsigned int policy_len,
			     unsigned int *tee_usage,
			     unsigned char *actual_policy,
			     unsigned int *actual_policy_len)
{
	int status = SMW_STATUS_OK;

	unsigned int value_size = 0;
	unsigned char *type = NULL;
	unsigned char *value = NULL;
	const unsigned char *p = policy;
	const unsigned char *end = policy + policy_len;
	unsigned char *q = actual_policy;
	bool policy_ignored = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!actual_policy) {
		*tee_usage = TEE_KEY_USAGE_ALL;
		return status;
	}

	*tee_usage = 0;

	smw_tlv_set_type(&q, POLICY_STR);

	while (p < end) {
		status = smw_tlv_read_element(&p, end, &type, &value,
					      &value_size);

		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing policy failed\n",
				       __func__);

			if (status == SMW_STATUS_INVALID_PARAM)
				status = SMW_STATUS_KEY_POLICY_ERROR;

			goto exit;
		}

		if (SMW_UTILS_STRCMP((char *)type, USAGE_STR))
			continue;

		if (!key_usage_to_value((char *)value, tee_usage)) {
			policy_ignored = true;
			continue;
		}

		if (SMW_UTILS_STRLEN((char *)value) + 1 < value_size)
			policy_ignored = true;

		smw_tlv_set_string(&q, USAGE_STR, (char *)value);
	}

	smw_tlv_set_length(actual_policy, q);

	SMW_DBG_ASSERT((unsigned int)(q - actual_policy) <= *actual_policy_len);
	*actual_policy_len = q - actual_policy;

	if (policy_ignored)
		status = SMW_STATUS_KEY_POLICY_WARNING_IGNORED;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * key_usage_to_string() - Convert TEE key usage value(s) to SMW's policy string
 * @str: String value of @usage bitmask (if NULL, calculates expected length)
 * @length: Maximum length of the @str
 * @usage: TEE key usage bitmask
 *
 * Return:
 * If @str is NULL, the expected length of @str
 * If @str is not NULL, the length of @str built
 * -1 in case of error (@str's length too small
 */
static int key_usage_to_string(unsigned char **str, int length,
			       unsigned int usage)
{
	unsigned char *p = NULL;
	int out_len = 0;
	int rem_len = length;
	int usage_len = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (str)
		p = *str;

	for (i = 0; i < ARRAY_SIZE(key_usage); i++) {
		if ((usage & key_usage[i].tee_usage) != key_usage[i].tee_usage)
			continue;

		usage_len = SMW_UTILS_STRLEN(key_usage[i].usage_str) + 1;
		usage_len = SMW_TLV_ELEMENT_LENGTH(USAGE_STR, usage_len);
		SMW_DBG_PRINTF(DEBUG, "Key usage (len=%u): USAGE=%s\n",
			       usage_len, key_usage[i].usage_str);
		if (p) {
			if (rem_len >= usage_len) {
				smw_tlv_set_string(&p, USAGE_STR,
						   key_usage[i].usage_str);
				rem_len -= usage_len;
			} else {
				out_len = -1;
				p = *str;
				break;
			}
		}

		out_len += usage_len;
	}

	if (str)
		*str = p;

	SMW_DBG_PRINTF(DEBUG, "%s return length %u\n", __func__, out_len);
	return out_len;
}

static int tee_set_key_policy(unsigned char **policy, unsigned int *policy_len,
			      unsigned int tee_usage)
{
	int status = SMW_STATUS_KEY_POLICY_ERROR;

	unsigned char *p = NULL;
	int usage_str_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Get the expected usage(s) string length */
	usage_str_len = key_usage_to_string(NULL, usage_str_len, tee_usage);
	if (usage_str_len == -1)
		goto exit;

	/* Calculate policy length and allocate the policy string */
	*policy_len = SMW_TLV_ELEMENT_LENGTH(POLICY_STR, usage_str_len);

	*policy = SMW_UTILS_CALLOC(1, *policy_len);
	if (!*policy) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	p = *policy;
	smw_tlv_set_type(&p, POLICY_STR);

	/* Build the policy string composed of the key usage */
	if (key_usage_to_string(&p, usage_str_len, tee_usage) ==
	    usage_str_len) {
		smw_tlv_set_length(*policy, p);
		status = SMW_STATUS_OK;
	}

exit:
	if (status != SMW_STATUS_OK && *policy) {
		SMW_UTILS_FREE(*policy);
		*policy = NULL;
		*policy_len = 0;
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
 * update_public_buffers() - Update public key buffers.
 * @key_desc: Pointer to key descriptor.
 * @cmd: OPTEE command operation.
 * @op: Pointer to operation structure to update.
 * @only_length: if true, update only the buffer length.
 *
 * In case of SMW_STATUS_OUTPUT_TOO_SHORT, public buffers length are updated
 * with expected length.
 *
 * Return:
 * SMW_STATUS_OK                - Success.
 * SMW_STATUS_INVALID_PARAM     - One of the parameter is invalid.
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer is too short
 * SMW_STATUS_OPERATION_FAILURE - No exported buffer
 */
static int update_public_buffers(struct smw_keymgr_descriptor *key_desc,
				 uint32_t cmd, TEEC_Operation *op,
				 bool only_length)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	int status_mod = SMW_STATUS_OPERATION_FAILURE;
	unsigned char *data = NULL;
	unsigned int length = 0;
	unsigned int param_idx = GEN_PUB_KEY_PARAM_IDX;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Export public key buffer */
	if (cmd == CMD_EXPORT_KEY)
		param_idx = EXP_PUB_KEY_PARAM_IDX;

	if (!only_length)
		data = op->params[param_idx].tmpref.buffer;

	length = op->params[param_idx].tmpref.size;

	status = smw_keymgr_update_public_buffer(key_desc, data, length);

	if (key_desc->identifier.type_id != SMW_CONFIG_KEY_TYPE_ID_RSA)
		goto exit;

	param_idx = GEN_MOD_PARAM_IDX;
	if (cmd == CMD_EXPORT_KEY)
		param_idx = EXP_MOD_PARAM_IDX;

	if (!only_length)
		data = op->params[param_idx].tmpref.buffer;

	if (op->params[param_idx].tmpref.size < UINT_MAX)
		length = op->params[param_idx].tmpref.size;

	status_mod = smw_keymgr_update_modulus_buffer(key_desc, data, length);
	if (status == SMW_STATUS_OK)
		status = status_mod;

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
 * set_params_exp_public_keys() - Set shared buffers parameters with
 *                                exported public keys.
 * @key_desc: Key descriptor.
 * @cmd: OPTEE command operation
 * @op: Pointer to operation structure to update.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_NO_KEY_BUFFER  - No key buffer defined
 * SMW_STATUS_INVALID_PARAM  - Invalid parameter
 * SMW_STATUS_ALLOC_FAILURE  - Memory allocation failure.
 */
static int set_params_exp_public_keys(struct smw_keymgr_descriptor *key_desc,
				      uint32_t cmd, TEEC_Operation *op)
{
	int status = SMW_STATUS_NO_KEY_BUFFER;

	unsigned char *pub_data = NULL;
	unsigned char *modulus = NULL;
	unsigned char *hex_modulus = NULL;
	unsigned char *hex_pub_data = NULL;
	unsigned int pub_len = 0;
	unsigned int modulus_len = 0;
	unsigned int param_idx = 0;

	pub_data = smw_keymgr_get_public_data(key_desc);
	if (!pub_data)
		goto exit;

	pub_len = smw_keymgr_get_public_length(key_desc);

	if (key_desc->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		modulus = smw_keymgr_get_modulus(key_desc);
		if (!modulus)
			goto exit;

		modulus_len = smw_keymgr_get_modulus_length(key_desc);

		/* Set modulus buffer */
		status = set_hex_exp_buffer(key_desc->format_id, modulus,
					    &hex_modulus, modulus_len);
		if (status != SMW_STATUS_OK)
			goto exit;

		param_idx = GEN_MOD_PARAM_IDX;
		if (cmd == CMD_EXPORT_KEY)
			param_idx = EXP_MOD_PARAM_IDX;

		status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT, param_idx,
					   hex_modulus, modulus_len, op);
		if (status != SMW_STATUS_OK)
			goto exit;
	}

	/* Set public buffer */
	status = set_hex_exp_buffer(key_desc->format_id, pub_data,
				    &hex_pub_data, pub_len);
	if (status != SMW_STATUS_OK)
		goto exit;

	param_idx = GEN_PUB_KEY_PARAM_IDX;
	if (cmd == CMD_EXPORT_KEY)
		param_idx = EXP_PUB_KEY_PARAM_IDX;

	status = set_tmpref_buffer(TEEC_MEMREF_TEMP_OUTPUT, param_idx,
				   hex_pub_data, pub_len, op);

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
 * SMW_STATUS_INVALID_PARAM	- Invalid parameter
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failure.
 */
static int set_params_gen_key(struct smw_keymgr_generate_key_args *key_args,
			      TEEC_Operation *op)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_attributes *key_attrs = &key_args->key_attributes;

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

	status = set_params_exp_public_keys(&key_args->key_descriptor,
					    CMD_GENERATE_KEY, op);
	if (status == SMW_STATUS_NO_KEY_BUFFER)
		status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * cmd_ta_delete_key() - Delete a key in TEE subsystem storage.
 * @id: Key id to delete.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int cmd_ta_delete_key(uint32_t id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	TEEC_Operation op = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!id)
		goto exit;

	/* params[0] = Key ID */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	/* Key research is done with Key ID */
	op.params[0].value.a = id;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_DELETE_KEY, &op);

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
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failure.
 * SMW_STATUS_OUTPUT_TOO_SHORT	- Output buffer is too short
 * SMW_STATUS_OPERATION_FAILURE	- Operation failed
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Subsytem failed.
 */
static int generate_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_INVALID_PARAM;
	int usage_status = SMW_STATUS_OK;
	struct smw_keymgr_generate_key_args *key_args = args;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct smw_keymgr_attributes *key_attrs;
	const struct key_info *key = NULL;
	struct keymgr_shared_params shared_params = { 0 };
	unsigned char *actual_policy = NULL;
	unsigned int actual_policy_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
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

	key_attrs = &key_args->key_attributes;

	if (key_attrs->policy && key_attrs->policy_len) {
		actual_policy_len =
			SMW_TLV_ELEMENT_LENGTH(POLICY_STR,
					       key_attrs->policy_len);
		actual_policy = SMW_UTILS_MALLOC(actual_policy_len);
		if (!actual_policy) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto exit;
		}
	}

	/* Set shared buffers parameters if needed */
	status = set_params_gen_key(key_args, &op);
	if (status != SMW_STATUS_OK)
		goto exit;

	if (key_attrs->persistence == SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT)
		shared_params.persistent_storage = true;

	shared_params.id = key_identifier->id;
	shared_params.security_size = key_identifier->security_size;
	shared_params.key_type = key->tee_key_type;
	usage_status =
		tee_set_key_usage(key_attrs->policy, key_attrs->policy_len,
				  &shared_params.key_usage, actual_policy,
				  &actual_policy_len);
	if (usage_status != SMW_STATUS_OK &&
	    usage_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		status = usage_status;
		goto exit;
	}

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
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status = update_public_buffers(&key_args->key_descriptor,
						   CMD_GENERATE_KEY, &op, true);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

	if (status != SMW_STATUS_OK)
		goto exit;

	/* Update key_identifier struct */
	status = smw_keymgr_get_privacy_id(key_identifier->type_id,
					   &key_identifier->privacy_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	key_identifier->subsystem_id = SUBSYSTEM_ID_TEE;
	key_identifier->id = shared_params.id;
	SMW_DBG_PRINTF(DEBUG, "%s: Key #%d is generated\n", __func__,
		       key_identifier->id);

	if (smw_keymgr_get_public_data(&key_args->key_descriptor))
		status = update_public_buffers(&key_args->key_descriptor,
					       CMD_GENERATE_KEY, &op, false);

exit:
	if (key_args &&
	    key_args->key_descriptor.format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		/* Free HEX public data buffer allocated */
		free_tmpref_buffer(GEN_PUB_KEY_PARAM_IDX, &op);

		/* Free HEX modulus buffer allocated */
		free_tmpref_buffer(GEN_MOD_PARAM_IDX, &op);
	}

	if (status != SMW_STATUS_OK) {
		(void)cmd_ta_delete_key(shared_params.id);

	} else if (usage_status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		if (actual_policy)
			smw_keymgr_set_attributes_list(key_attrs, actual_policy,
						       actual_policy_len);

		status = usage_status;
	}

	if (actual_policy)
		SMW_UTILS_FREE(actual_policy);

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
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_delete_key_args *key_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_args)
		goto exit;

	status = cmd_ta_delete_key(key_args->key_descriptor.identifier.id);

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
	int usage_status = SMW_STATUS_OK;
	unsigned int key_size_bytes = 0;
	struct smw_keymgr_import_key_args *key_args = args;
	struct smw_keymgr_identifier *key_identifier = NULL;
	struct smw_keymgr_attributes *key_attrs;
	const struct key_info *key = NULL;
	struct keymgr_shared_params shared_params = { 0 };
	unsigned char *actual_policy = NULL;
	unsigned int actual_policy_len = 0;

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

	key_attrs = &key_args->key_attributes;

	if (key_attrs->policy && key_attrs->policy_len) {
		actual_policy_len =
			SMW_TLV_ELEMENT_LENGTH(POLICY_STR,
					       key_attrs->policy_len);
		actual_policy = SMW_UTILS_MALLOC(actual_policy_len);
		if (!actual_policy) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto exit;
		}
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

	shared_params.id = key_identifier->id;
	shared_params.security_size = key_identifier->security_size;
	shared_params.key_type = key->tee_key_type;

	if (key_attrs->persistence == SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT)
		shared_params.persistent_storage = true;

	usage_status =
		tee_set_key_usage(key_attrs->policy, key_attrs->policy_len,
				  &shared_params.key_usage, actual_policy,
				  &actual_policy_len);
	if (usage_status != SMW_STATUS_OK &&
	    usage_status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		status = usage_status;
		goto exit;
	}

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

	if (status == SMW_STATUS_OK &&
	    usage_status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
		status = usage_status;

	if (actual_policy) {
		if (status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
			smw_keymgr_set_attributes_list(key_attrs, actual_policy,
						       actual_policy_len);

		SMW_UTILS_FREE(actual_policy);
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
 * SMW_STATUS_NO_KEY_BUFFER		- No key buffer defined.
 */
static int export_key(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_export_key_args *key_args = args;
	struct smw_keymgr_descriptor *key_descriptor = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_descriptor = &key_args->key_descriptor;

	status = check_export_key_config(key_descriptor);
	if (status != SMW_STATUS_OK)
		goto exit;

	status =
		set_params_exp_public_keys(key_descriptor, CMD_EXPORT_KEY, &op);
	if (status != SMW_STATUS_OK)
		goto exit;
	/*
	 * params[0] = TEE Key ID, Key security size.
	 * params[1] = Public key buffer.
	 * params[2] = Modulus buffer (RSA key) or none.
	 * params[3] = None.
	 */
	SET_TEEC_PARAMS_TYPE(op.paramTypes, TEEC_VALUE_INPUT, 0);
	op.params[0].value.a = key_descriptor->identifier.id;
	op.params[0].value.b = key_descriptor->identifier.security_size;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_EXPORT_KEY, &op);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		tmp_status = update_public_buffers(key_descriptor,
						   CMD_EXPORT_KEY, &op, true);
		if (tmp_status != SMW_STATUS_OK)
			status = tmp_status;
	}

	if (status != SMW_STATUS_OK)
		goto exit;

	/* Export public key */
	status = update_public_buffers(key_descriptor, CMD_EXPORT_KEY, &op,
				       false);

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

/**
 * get_key_lengths() - Get the key buffer lengths of a key handles by OPTEE.
 * @args: Key descriptor.
 *
 * Return:
 * SMW_STATUS_OK                 - Success.
 * SMW_STATUS_INVALID_PARAM      - One of the parameter is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE  - Trusted application failed.
 */
static int get_key_lengths(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_descriptor *key_desc = NULL;
	enum smw_config_key_type_id key_type = SMW_CONFIG_KEY_TYPE_ID_INVALID;
	enum tee_key_type tee_key_type = TEE_KEY_TYPE_ID_INVALID;
	unsigned int length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_desc = args;

	/*
	 * params[0].value.a = TEE Key ID.
	 * params[0].value.b = TEE Key type returned.
	 * params[1].value.a = Public key buffer length.
	 * params[1].value.b = Modulus buffer (RSA key) length.
	 * params[2].value.a = Private key buffer length.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_NONE);

	op.params[GET_KEY_LENGTHS_KEY_ID_IDX].value.a = key_desc->identifier.id;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_GET_KEY_LENGTHS, &op);

	if (status != SMW_STATUS_OK)
		goto exit;

	if (op.params[GET_KEY_LENGTHS_KEY_ID_IDX].value.b >
	    TEE_KEY_TYPE_ID_NB) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	tee_key_type = op.params[GET_KEY_LENGTHS_KEY_ID_IDX].value.b;
	key_type = key_type_tee_to_smw(tee_key_type);
	if (key_desc->identifier.type_id != key_type) {
		SMW_DBG_PRINTF(DEBUG, "User/TEE key type error %d != %d\n",
			       key_type, tee_key_type);
		status = SMW_STATUS_INVALID_PARAM;
	} else {
		/*
		 * No need to check if it's an asymmetric key and the
		 * type of the key RSA or not.
		 * Key function setting the buffer length is setup
		 * according to key type.
		 */
		length = op.params[GET_KEY_LENGTHS_PUBKEYS_IDX].value.a;
		status =
			smw_keymgr_update_public_buffer(key_desc, NULL, length);

		length = op.params[GET_KEY_LENGTHS_PUBKEYS_IDX].value.b;
		tmp_status = smw_keymgr_update_modulus_buffer(key_desc, NULL,
							      length);
		if (status == SMW_STATUS_OK)
			status = tmp_status;

		length = op.params[GET_KEY_LENGTHS_PRIVKEY_IDX].value.a;
		tmp_status = smw_keymgr_update_private_buffer(key_desc, NULL,
							      length);
		if (status == SMW_STATUS_OK)
			status = tmp_status;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_key_attributes() - Get the key attributes of a key handles by OPTEE.
 * @args: Key attributes parameters.
 *
 * Return:
 * SMW_STATUS_OK                 - Success.
 * SMW_STATUS_INVALID_PARAM      - One of the parameter is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE  - Trusted application failed.
 */
static int get_key_attributes(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_get_key_attributes_args *key_attrs = NULL;
	enum tee_key_type tee_type = TEE_KEY_TYPE_ID_INVALID;
	unsigned int tee_usage = 0;
	unsigned char *policy_list = NULL;
	unsigned int policy_list_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto exit;

	key_attrs = args;

	/*
	 * params[0].value.a = TEE Key ID.
	 * params[1].value.a = TEE Key type returned.
	 * params[1].value.b = TEE Key usage returned.
	 * params[2].value.a = TEE keypair/public type returned.
	 * params[2].value.b = TEE key persistent flag returned.
	 * params[3].value.a = TEE Key size returned.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT);

	op.params[GET_KEY_ATTRS_KEY_ID_IDX].value.a = key_attrs->identifier.id;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_GET_KEY_ATTRIBUTES, &op);

	if (status != SMW_STATUS_OK)
		goto exit;

	if (op.params[GET_KEY_ATTRS_KEY_TYPE_IDX].value.a >
	    TEE_KEY_TYPE_ID_NB) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	tee_type = op.params[GET_KEY_ATTRS_KEY_TYPE_IDX].value.a;
	tee_usage = op.params[GET_KEY_ATTRS_KEY_USAGE_IDX].value.b;

	switch (op.params[GET_KEY_ATTRS_KEYPAIR_FLAG_IDX].value.a) {
	case TEE_KEY_PAIR:
		key_attrs->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
		break;

	case TEE_KEY_PRIVATE:
		key_attrs->identifier.privacy_id =
			SMW_KEYMGR_PRIVACY_ID_PRIVATE;
		break;

	case TEE_KEY_PUBLIC:
		key_attrs->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	if (op.params[GET_KEY_ATTRS_PERSISTENT_FLAG_IDX].value.b)
		key_attrs->identifier.persistence_id =
			SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT;
	else
		key_attrs->identifier.persistence_id =
			SMW_KEYMGR_PERSISTENCE_ID_TRANSIENT;

	key_attrs->identifier.storage_id = 0;
	key_attrs->identifier.type_id = key_type_tee_to_smw(tee_type);
	key_attrs->identifier.security_size =
		op.params[GET_KEY_ATTRS_KEY_SIZE_IDX].value.a;

	status = tee_set_key_policy(&policy_list, &policy_list_length,
				    tee_usage);
	if (status == SMW_STATUS_OK)
		smw_keymgr_set_policy(key_attrs, policy_list,
				      policy_list_length);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_shared_key_size() - Get shared key memory size.
 * @key_descriptor: Pointer to key descriptor.
 * @privacy: Key privacy.
 * @memory_size: Size to update.
 *
 * The parameter @memory_size is not updated if an error is returned.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Key privacy is invalid.
 */
static int get_shared_key_size(struct smw_keymgr_descriptor *key_descriptor,
			       enum smw_keymgr_privacy_id privacy,
			       unsigned int *memory_size)
{
	unsigned int pub_size = 0;
	unsigned int priv_size = 0;

	switch (privacy) {
	case SMW_KEYMGR_PRIVACY_ID_PAIR:
		if (!smw_keymgr_get_public_data(key_descriptor) ||
		    !smw_keymgr_get_private_data(key_descriptor))
			return SMW_STATUS_INVALID_PARAM;

		pub_size = smw_keymgr_get_public_length(key_descriptor);
		priv_size = smw_keymgr_get_private_length(key_descriptor);

		if (!pub_size || !priv_size)
			return SMW_STATUS_INVALID_PARAM;
		break;

	case SMW_KEYMGR_PRIVACY_ID_PRIVATE:
		if (!smw_keymgr_get_private_data(key_descriptor))
			return SMW_STATUS_INVALID_PARAM;

		priv_size = smw_keymgr_get_private_length(key_descriptor);
		if (!priv_size)
			return SMW_STATUS_INVALID_PARAM;

		break;

	case SMW_KEYMGR_PRIVACY_ID_PUBLIC:
		if (!smw_keymgr_get_public_data(key_descriptor))
			return SMW_STATUS_INVALID_PARAM;

		pub_size = smw_keymgr_get_public_length(key_descriptor);
		if (!pub_size)
			return SMW_STATUS_INVALID_PARAM;

		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	*memory_size = smw_keymgr_get_modulus_length(key_descriptor) +
		       pub_size + priv_size;

	return SMW_STATUS_OK;
}

/**
 * fill_shared_key_memory() - Fill shared memory with key buffer.
 * @key_descriptor: Pointer to key descriptor.
 * @privacy: Key privacy.
 * @shared_key: Pointer to TEEC shared memory structure.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- Key privacy is invalid.
 */
static int fill_shared_key_memory(struct smw_keymgr_descriptor *key_descriptor,
				  enum smw_keymgr_privacy_id privacy,
				  TEEC_SharedMemory *shared_key)
{
	void *key_buffer = shared_key->buffer;
	unsigned char *public_data = NULL;
	unsigned char *private_data = NULL;
	unsigned int public_length = 0;
	unsigned int private_length = 0;

	switch (privacy) {
	case SMW_KEYMGR_PRIVACY_ID_PAIR:
		public_data = smw_keymgr_get_public_data(key_descriptor);
		public_length = smw_keymgr_get_public_length(key_descriptor);
		private_data = smw_keymgr_get_private_data(key_descriptor);
		private_length = smw_keymgr_get_private_length(key_descriptor);

		if (!public_data || !public_length || !private_data ||
		    !private_length)
			return SMW_STATUS_INVALID_PARAM;

		break;

	case SMW_KEYMGR_PRIVACY_ID_PRIVATE:
		private_data = smw_keymgr_get_private_data(key_descriptor);
		private_length = smw_keymgr_get_private_length(key_descriptor);

		if (!private_data || !private_length)
			return SMW_STATUS_INVALID_PARAM;

		break;

	case SMW_KEYMGR_PRIVACY_ID_PUBLIC:
		public_data = smw_keymgr_get_public_data(key_descriptor);
		public_length = smw_keymgr_get_public_length(key_descriptor);
		if (!public_data || !public_length)
			return SMW_STATUS_INVALID_PARAM;

		break;

	default:
		return SMW_STATUS_INVALID_PARAM;
	}

	if (public_data) {
		SMW_UTILS_MEMCPY(key_buffer, public_data, public_length);
		key_buffer += public_length;
	}

	if (private_data) {
		SMW_UTILS_MEMCPY(key_buffer, private_data, private_length);
		key_buffer += private_length;
	}

	if (smw_keymgr_get_modulus(key_descriptor)) {
		SMW_UTILS_MEMCPY(key_buffer,
				 smw_keymgr_get_modulus(key_descriptor),
				 smw_keymgr_get_modulus_length(key_descriptor));
	}

	return SMW_STATUS_OK;
}

int copy_keys_to_shm(TEEC_SharedMemory *shm,
		     struct smw_keymgr_descriptor *key_descriptor,
		     enum smw_keymgr_privacy_id privacy)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int memory_size;
	TEEC_Result result;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!shm || !key_descriptor)
		goto exit;

	status = get_shared_key_size(key_descriptor, privacy, &memory_size);
	if (status != SMW_STATUS_OK)
		goto exit;

	shm->size = memory_size;
	shm->flags = TEEC_MEM_INPUT;

	result = TEEC_AllocateSharedMemory(get_tee_context_ptr(), shm);
	if (result != TEEC_SUCCESS) {
		status = convert_tee_result(result);
		goto exit;
	}

	status = fill_shared_key_memory(key_descriptor, privacy, shm);

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
		*status = import_key(args);
		break;
	case OPERATION_ID_EXPORT_KEY:
		*status = export_key(args);
		break;
	case OPERATION_ID_GET_KEY_LENGTHS:
		*status = get_key_lengths(args);
		break;
	case OPERATION_ID_GET_KEY_ATTRIBUTES:
		*status = get_key_attributes(args);
		break;
	default:
		return false;
	}

	return true;
}
