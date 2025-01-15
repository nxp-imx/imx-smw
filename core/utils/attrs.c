// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_crypto.h"

#include "config.h"
#include "builtin_macros.h"
#include "debug.h"

#define HASH_ALGO(_id)                                                         \
	{                                                                      \
		.attr = SMW_ATTR_HASH_##_id,                                   \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id                       \
	}

static const struct hash_algo {
	smw_attr_algo_t attr;
	enum smw_config_hash_algo_id algo_id;
} hash_algo_list[] = { { .attr = SMW_ATTR_HASH_NONE,
			 .algo_id = SMW_CONFIG_HASH_ALGO_ID_INVALID },
		       { .attr = SMW_ATTR_HASH_ANY,
			 .algo_id = SMW_CONFIG_HASH_ALGO_ID_INVALID },
		       HASH_ALGO(MD5),
		       HASH_ALGO(SHA1),
		       HASH_ALGO(SHA224),
		       HASH_ALGO(SHA256),
		       HASH_ALGO(SHA384),
		       HASH_ALGO(SHA512),
		       HASH_ALGO(SHA3_224),
		       HASH_ALGO(SHA3_256),
		       HASH_ALGO(SHA3_384),
		       HASH_ALGO(SHA3_512),
		       HASH_ALGO(SM3) };

int smw_utils_hash_attr_to_algo_id(smw_attr_algo_t attr,
				   enum smw_config_hash_algo_id *algo_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(hash_algo_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (SMW_ATTR_GET_HASH(attr) == hash_algo_list[i].attr) {
			*algo_id = hash_algo_list[i].algo_id;

			SMW_DBG_PRINTF(DEBUG, "Hash algorithm: %d\n", *algo_id);

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define SIGN_ALGO(_id)                                                         \
	{                                                                      \
		.attr = SMW_ATTR_ALGO_##_id,                                   \
		.algo_id = SMW_CONFIG_SIGN_ALGO_ID_##_id                       \
	}

static const struct {
	smw_attr_algo_t attr;
	enum smw_config_sign_algo_id algo_id;
} sign_algo_list[] = {
	SIGN_ALGO(DEFAULT), SIGN_ALGO(ECDSA), SIGN_ALGO(EDDSA),
	SIGN_ALGO(DSA),	    SIGN_ALGO(RSA),   SIGN_ALGO(TLS_1_2)
};

int smw_utils_sign_attr_to_algo_id(smw_attr_algo_t attr,
				   enum smw_config_sign_algo_id *algo_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(sign_algo_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (SMW_ATTR_GET_ALGO(attr) == sign_algo_list[i].attr) {
			*algo_id = sign_algo_list[i].algo_id;

			SMW_DBG_PRINTF(DEBUG, "Signature algo: %d\n", *algo_id);

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define SIGN_TYPE(_id)                                                         \
	{                                                                      \
		.attr = SMW_ATTR_MODE_##_id,                                   \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_id                       \
	}

static const struct {
	smw_attr_algo_t attr;
	enum smw_config_sign_type_id type_id;
} sign_type_list[] = { { .attr = SMW_ATTR_MODE_NONE,
			 .type_id = SMW_CONFIG_SIGN_TYPE_ID_INVALID },
		       { .attr = SMW_ATTR_MODE_ANY,
			 .type_id = SMW_CONFIG_SIGN_TYPE_ID_DEFAULT },
		       { .attr = SMW_ATTR_CURVE_ED25519,
			 .type_id = SMW_CONFIG_SIGN_TYPE_ID_DEFAULT },
		       SIGN_TYPE(CMAC),
		       SIGN_TYPE(PKCS1_1_5),
		       SIGN_TYPE(PSS),
		       SIGN_TYPE(CLIENT),
		       SIGN_TYPE(SERVER) };

int smw_utils_sign_type_attr_to_id(smw_attr_algo_t attr,
				   enum smw_config_sign_type_id *type_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(sign_type_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (SMW_ATTR_GET_MODE(attr) == sign_type_list[i].attr) {
			*type_id = sign_type_list[i].type_id;

			SMW_DBG_PRINTF(DEBUG, "Signature type: %d\n", *type_id);

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
