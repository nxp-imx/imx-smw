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
	HASH_ALGO(SHA3_384, SHA3_384, 48), HASH_ALGO(SHA3_512, SHA3_512, 64)
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
