// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
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

static const struct ele_hash_algo hash_algos[] = {
	HASH_ALGO(MD5, MD5, 16),	   HASH_ALGO(SHA1, SHA_1, 20),
	HASH_ALGO(SHA224, SHA_224, 28),	   HASH_ALGO(SHA256, SHA_256, 32),
	HASH_ALGO(SHA384, SHA_384, 48),	   HASH_ALGO(SHA512, SHA_512, 64),
	HASH_ALGO(SHA3_224, SHA3_224, 28), HASH_ALGO(SHA3_256, SHA3_256, 32),
	HASH_ALGO(SHA3_384, SHA3_384, 48), HASH_ALGO(SHA3_512, SHA3_512, 64),
	HASH_ALGO(SHAKE256, SHAKE_256, 32)
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
	CIPHER_ALGO(AES, CBC),
	CIPHER_ALGO(AES, CFB),
	CIPHER_ALGO(AES, CTR),
	CIPHER_ALGO(AES, ECB),
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

void ele_free_hash_context(struct hash_context *ctx)
{
	if (ctx->ele_ctx) {
		SMW_UTILS_FREE(ctx->ele_ctx);
		ctx->ele_ctx = NULL;
		ctx->ele_ctx_size = 0;
	}
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

static bool is_imx91_or_imx93(void)
{
	bool is_imx91_or_imx93 = false;

	uint16_t soc_id = se_get_soc_id();

	SMW_DBG_PRINTF(DEBUG, "soc_id = 0X%x\n", soc_id);

	if (soc_id == SOC_IMX91 || soc_id == SOC_IMX93)
		is_imx91_or_imx93 = true;

	return is_imx91_or_imx93;
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

static bool is_conversion_req(enum smw_config_key_type_id type_id)
{
	bool is_conversion_req = false;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ED25519:
	case SMW_CONFIG_KEY_TYPE_ID_X25519:
	case SMW_CONFIG_KEY_TYPE_ID_ED448:
		is_conversion_req = true;
		break;

	default:
		break;
	}

	return is_conversion_req;
}

int check_and_convert_endian(unsigned char *src, unsigned char *dst,
			     unsigned int size,
			     enum smw_config_key_type_id type_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	if (!src || size == 0)
		goto end;

	status = SMW_STATUS_OK;

	if (!is_imx91_or_imx93() || !is_conversion_req(type_id)) {
		SMW_DBG_PRINTF(VERBOSE, "%s conversion not required\n",
			       __func__);
		goto end;
	}

	status = convert_endian(src, dst, size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

int check_and_convert_sign_endian(unsigned char *sign,
				  unsigned char *converted_sign,
				  unsigned int sign_len,
				  enum smw_config_key_type_id type_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int part_size = 0;

	if (!sign || sign_len == 0)
		return status;

	status = SMW_STATUS_OK;

	if (!is_imx91_or_imx93() || !is_conversion_req(type_id))
		return status;

	part_size = sign_len / 2;

	/*
	 * The signature is a concatenation of two components: R and S.
	 * Convert the endianness of each component (R and S) individually,
	 * then concatenate the results to form the final converted signature.
	 */
	if (converted_sign) {
		status = convert_endian(sign, converted_sign, part_size);
		if (status == SMW_STATUS_OK)
			status = convert_endian(sign + part_size,
						converted_sign + part_size,
						part_size);
	} else {
		status = convert_endian(sign, NULL, part_size);
		if (status == SMW_STATUS_OK)
			status = convert_endian(sign + part_size, NULL,
						part_size);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}
