// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include "compiler.h"
#include "smw_osal.h"

#include "config.h"
#include "debug.h"
#include "utils.h"

#include "common.h"

#define HASH_ALGO(_id, _ele_id, _length)                                       \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.ele_algo = HSM_HASH_ALGO_##_ele_id, .length = _length         \
	}

/*
 * https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf table 4
 * gives the digest length corresponding to the security strenghs.
 * In case of SHAKE256, the minimum security strengh is 256 bits requesting
 * 512 bits for the digest length.
 */
static const struct ele_hash_algo hash_algos[] = {
	HASH_ALGO(MD5, MD5, 16),	   HASH_ALGO(SHA1, SHA_1, 20),
	HASH_ALGO(SHA224, SHA_224, 28),	   HASH_ALGO(SHA256, SHA_256, 32),
	HASH_ALGO(SHA384, SHA_384, 48),	   HASH_ALGO(SHA512, SHA_512, 64),
	HASH_ALGO(SHA3_224, SHA3_224, 28), HASH_ALGO(SHA3_256, SHA3_256, 32),
	HASH_ALGO(SHA3_384, SHA3_384, 48), HASH_ALGO(SHA3_512, SHA3_512, 64),
	HASH_ALGO(SHAKE256, SHAKE_256, 64)
};

const struct ele_hash_algo *
ele_get_hash_algo(enum smw_config_hash_algo_id algo_id)
{
	const struct ele_hash_algo *hash_algo = NULL;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algos[i].algo_id == algo_id) {
			hash_algo = &hash_algos[i];
			break;
		}
	}

	return hash_algo;
}

#define CIPHER_ALGO(_key_type_id, _cipher_mode_id)                             \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.cipher_mode_id = SMW_CONFIG_CIPHER_MODE_ID_##_cipher_mode_id, \
		.cipher_algo = HSM_CIPHER_ONE_GO_ALGO_##_cipher_mode_id        \
	}

static const struct {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_cipher_mode_id cipher_mode_id;
	hsm_op_cipher_one_go_algo_t cipher_algo;
} cipher_algos[] = {
	CIPHER_ALGO(AES, CBC), CIPHER_ALGO(AES, CFB), CIPHER_ALGO(AES, CTR),
	CIPHER_ALGO(AES, OFB), CIPHER_ALGO(AES, ECB),
};

int ele_set_cipher_algo(enum smw_config_key_type_id key_type_id,
			enum smw_config_cipher_mode_id cipher_mode_id,
			hsm_op_cipher_one_go_algo_t *cipher_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_algos); i++) {
		if (key_type_id == cipher_algos[i].key_type_id &&
		    cipher_mode_id == cipher_algos[i].cipher_mode_id) {
			*cipher_algo = cipher_algos[i].cipher_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak int ele_get_device_info(struct subsystem_context *ele_ctx)
{
	(void)ele_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

int ele_get_key_store_id(uint32_t *keystore_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct se_info info = { 0 };

	if (smw_utils_get_subsystem_info(SMW_SUBSYSTEM_NAME_ELE, &info))
		goto end;

	*keystore_id = info.storage_id;
	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int convert_endian(unsigned char *src, unsigned char *dst,
			  unsigned int size)
{
	unsigned int i = 0;

	if (!src || size == 0)
		return SMW_STATUS_INVALID_PARAM;

	if (dst) {
		for (; i < size; i++)
			dst[i] = src[size - 1 - i];
	} else {
		for (; i < size / 2; i++) {
			src[i] ^= src[size - 1 - i];
			src[size - 1 - i] ^= src[i];
			src[i] ^= src[size - 1 - i];
		}
	}

	return SMW_STATUS_OK;
}

static int is_conversion_req(struct subsystem_context *ele_ctx,
			     enum smw_config_key_type_id type_id, bool *convert)
{
	int status = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;

	*convert = false;

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!info->edwards_be)
		goto end;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ED25519:
	case SMW_CONFIG_KEY_TYPE_ID_X25519:
	case SMW_CONFIG_KEY_TYPE_ID_ED448:
	case SMW_CONFIG_KEY_TYPE_ID_X448:
		SMW_DBG_PRINTF(VERBOSE, "%s conversion required\n", __func__);
		*convert = true;
		break;

	default:
		break;
	}

end:
	return status;
}

int check_and_convert_endian(struct subsystem_context *ele_ctx,
			     unsigned char *src, unsigned char **dst,
			     unsigned int size,
			     enum smw_config_key_type_id type_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *out = NULL;
	bool convert = false;

	if (!src || size == 0)
		goto end;

	status = is_conversion_req(ele_ctx, type_id, &convert);
	if (status != SMW_STATUS_OK || !convert)
		goto end;

	if (dst) {
		*dst = SMW_UTILS_MALLOC(size);
		if (!*dst) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		out = *dst;
	}

	status = convert_endian(src, out, size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

int check_and_convert_sign_endian(struct subsystem_context *ele_ctx,
				  unsigned char *sign,
				  unsigned char **converted_sign,
				  unsigned int sign_len,
				  enum smw_config_key_type_id type_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	bool convert = false;
	unsigned int part_size = 0;
	unsigned char *out_r = NULL;
	unsigned char *out_s = NULL;

	if (!sign || sign_len == 0)
		goto end;

	status = is_conversion_req(ele_ctx, type_id, &convert);
	if (status != SMW_STATUS_OK || !convert)
		goto end;

	part_size = sign_len / 2;

	/*
	 * The signature is a concatenation of two components: R and S.
	 * Convert the endianness of each component (R and S) individually,
	 * then concatenate the results to form the final converted signature.
	 */
	if (converted_sign) {
		*converted_sign = SMW_UTILS_MALLOC(sign_len);
		if (!*converted_sign) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		out_r = *converted_sign;
		out_s = *converted_sign + part_size;
	}

	status = convert_endian(sign, out_r, part_size);
	if (status == SMW_STATUS_OK)
		status = convert_endian(sign + part_size, out_s, part_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

int check_aead_multi_part_support(struct subsystem_context *ele_ctx,
				  bool *is_multi_part_supported)
{
	int status = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;

	*is_multi_part_supported = false;

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	*is_multi_part_supported = info->aead_multipart;

end:
	return status;
}

int ele_calculate_expected_output_len(struct crypto_output_params *params,
				      unsigned int *expected_output_len)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int output_len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!params || !expected_output_len)
		goto end;

	*expected_output_len = 0;

	switch (params->op_step) {
	case SMW_OP_STEP_ONESHOT:
		output_len = params->input_len;
		break;

	case SMW_OP_STEP_UPDATE:
		/*
		 * For UPDATE: output may be less than input due to buffering
		 * Return input_len as maximum estimate
		 */
		output_len = params->input_len;
		break;

	case SMW_OP_STEP_FINAL:
		/*
		 * For FINAL: output = remaining_buffered + input
		 */
		output_len = params->remaining_buffered_len;

		if (INC_OVERFLOW(output_len, params->input_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Invalid operation step: %d\n",
			       params->op_step);
		goto end;
	}

	/*
	 * Add tag length if set
	 * tag_len is non-zero ONLY when tag should be added to output:
	 * - AEAD encryption with tag part of output buffer: tag_len = ELE_TAG_LEN
	 * - AEAD encryption with dedicated tag field: tag_len = 0 (not added)
	 * - Decryption: tag_len = 0 (no tag in output)
	 * - Cipher: tag_len = 0 (no tag)
	 */
	if ((params->op_step == SMW_OP_STEP_ONESHOT ||
	     params->op_step == SMW_OP_STEP_FINAL) &&
	    params->tag_len > 0) {
		if (INC_OVERFLOW(output_len, params->tag_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	*expected_output_len = output_len;
	SMW_DBG_PRINTF(VERBOSE, "expected output length = %u\n",
		       *expected_output_len);
	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_update_buffered_len(unsigned int *remaining_buffered_len,
			    unsigned int input_len, unsigned int output_len)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int buffered_bytes = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!remaining_buffered_len)
		goto end;

	/*
	 * Calculate newly buffered bytes for this UPDATE operation
	 * buffered_bytes = input_len - output_len
	 *
	 * The subsystem may buffer incomplete blocks, so output can be
	 * less than input. The difference is buffered internally.
	 */
	if (SUB_OVERFLOW(input_len, output_len, &buffered_bytes)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	if (INC_OVERFLOW(*remaining_buffered_len, buffered_bytes)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	SMW_DBG_PRINTF(VERBOSE, "remaining buffered len = %u\n",
		       *remaining_buffered_len);

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int open_cipher_service(struct hdl *hdl, hsm_hdl_t *cipher_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	open_svc_cipher_args_t open_cipher_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_cipher_service(hdl->key_store, &open_cipher_args,
				      cipher_hdl);

	SMW_DBG_PRINTF(DEBUG, "cipher_hdl: %u\n", *cipher_hdl);

	SMW_DBG_PRINTF(VERBOSE, "hsm_open_cipher_service returned %d\n", err);

	return ele_convert_err(err);
}

int close_cipher_service(hsm_hdl_t cipher_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "cipher_hdl: %u\n", cipher_hdl);

	if (cipher_hdl)
		err = hsm_close_cipher_service(cipher_hdl);

	SMW_DBG_PRINTF(VERBOSE, "hsm_close_cipher_service returned %d\n", err);

	return ele_convert_err(err);
}

__weak void ele_free_hash_context(struct smw_op_context *ctx)
{
	(void)ctx;
}

__weak int ele_copy_hash_context(struct smw_op_context *src_ctx,
				 struct smw_op_context *dst_ctx)
{
	(void)src_ctx;
	(void)dst_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak void ele_free_sign_context(struct smw_op_context *ctx)
{
	(void)ctx;
}

__weak int ele_copy_sign_context(struct smw_op_context *src_ctx,
				 struct smw_op_context *dst_ctx)
{
	(void)src_ctx;
	(void)dst_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int tls_mac_finish(struct hdl *hdl, void *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak void ele_free_aead_context(struct smw_op_context *ctx)
{
	(void)ctx;
}

__weak int ele_copy_aead_context(struct smw_op_context *src_ctx,
				 struct smw_op_context *dst_ctx)
{
	(void)src_ctx;
	(void)dst_ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int ele_cancel_aead_op(struct smw_op_context *ctx)
{
	(void)ctx;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
