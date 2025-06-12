// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */
#include <inttypes.h>

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

#define SIGN_ALGO_ECDSA(_class, _curve, _type)                                 \
	{                                                                      \
		.is_curve = true, .class = SMW_ATTR_CLASS_##_class,            \
		.algo = SMW_ATTR_ALGO_ECDSA, .param = 0,                       \
		.curve = SMW_ATTR_CURVE_##_curve,                              \
		.algo_id = SMW_CONFIG_SIGN_ALGO_ID_ECDSA,                      \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type                     \
	}

#define SIGN_ALGO_EDDSA(_class, _algo, _curve, _param, _type)                  \
	{                                                                      \
		.is_curve = true, .class = SMW_ATTR_CLASS_##_class,            \
		.algo = SMW_ATTR_ALGO_##_algo,                                 \
		.param = SMW_ATTR_SIGN_PARAM_EDDSA_##_param,                   \
		.curve = SMW_ATTR_CURVE_##_curve,                              \
		.algo_id = SMW_CONFIG_SIGN_ALGO_ID_EDDSA,                      \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type                     \
	}

#define SIGN_ALGO_MODE(_class, _algo, _mode, _algo_id, _type)                  \
	{                                                                      \
		.is_curve = false, .class = SMW_ATTR_CLASS_##_class,           \
		.algo = SMW_ATTR_ALGO_##_algo, .param = 0,                     \
		.mode = SMW_ATTR_MODE_##_mode,                                 \
		.algo_id = SMW_CONFIG_SIGN_ALGO_ID_##_algo_id,                 \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type                     \
	}

#define SIGN_ALGO_TLS(_class, _algo, _type)                                    \
	{                                                                      \
		.is_curve = false, .class = SMW_ATTR_CLASS_##_class,           \
		.algo = SMW_ATTR_ALGO_##_algo, .param = 0,                     \
		.mode = SMW_ATTR_MODE_##_type,                                 \
		.algo_id = SMW_CONFIG_SIGN_ALGO_ID_##_algo,                    \
		.type_id = SMW_CONFIG_SIGN_TYPE_ID_##_type                     \
	}
static const struct {
	smw_attr_algo_t class;
	smw_attr_algo_t algo;
	smw_attr_algo_t param;

	bool is_curve;
	union {
		smw_attr_algo_t mode;
		smw_attr_algo_t curve;
	};

	enum smw_config_sign_algo_id algo_id;
	enum smw_config_sign_type_id type_id;
} sign_list[] = {
	SIGN_ALGO_ECDSA(ASYMMETRIC_SIGNATURE, ANY, DEFAULT),
	SIGN_ALGO_EDDSA(ASYMMETRIC_SIGNATURE, EDDSA, ANY, NONE, PURE_EDDSA),
	SIGN_ALGO_EDDSA(ASYMMETRIC_SIGNATURE, EDDSA, ED25519, PREHASHED,
			EDDSA_PH),
	SIGN_ALGO_EDDSA(ASYMMETRIC_SIGNATURE, EDDSA, ED25519, CONTEXT,
			EDDSA_CTX),
	SIGN_ALGO_MODE(ASYMMETRIC_SIGNATURE, DSA, NONE, DSA, DEFAULT),
	SIGN_ALGO_MODE(ASYMMETRIC_SIGNATURE, RSA, NONE, RSA, DEFAULT),
	SIGN_ALGO_MODE(ASYMMETRIC_SIGNATURE, RSA, ANY, RSA, DEFAULT),
	SIGN_ALGO_MODE(ASYMMETRIC_SIGNATURE, RSA, PKCS1_1_5, RSA, PKCS1_1_5),
	SIGN_ALGO_MODE(ASYMMETRIC_SIGNATURE, RSA, PSS, RSA, PSS),
	SIGN_ALGO_TLS(ASYMMETRIC_SIGNATURE, TLS_1_2, CLIENT),
	SIGN_ALGO_TLS(ASYMMETRIC_SIGNATURE, TLS_1_2, SERVER),
	SIGN_ALGO_MODE(KEY_ATTESTATION, AES, CMAC, DEFAULT, CMAC),
	SIGN_ALGO_ECDSA(KEY_ATTESTATION, ANY, DEFAULT),
};

int smw_utils_sign_attr_to_ids(smw_attr_algo_t attr,
			       enum smw_config_sign_algo_id *algo_id,
			       enum smw_config_sign_type_id *type_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(sign_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < size; i++) {
		if (sign_list[i].class != SMW_ATTR_GET_CLASS(attr))
			continue;

		if (sign_list[i].algo != SMW_ATTR_GET_ALGO(attr))
			continue;

		if (sign_list[i].is_curve) {
			if (sign_list[i].curve != SMW_ATTR_CURVE_ANY &&
			    sign_list[i].curve != SMW_ATTR_GET_CURVE(attr))
				continue;
		} else if (sign_list[i].mode != SMW_ATTR_GET_MODE(attr)) {
			continue;
		}

		if (sign_list[i].algo == SMW_ATTR_ALGO_EDDSA) {
			if (SMW_ATTR_GET_SIGN_PARAM(attr) != sign_list[i].param)
				continue;
		}

		*algo_id = sign_list[i].algo_id;
		*type_id = sign_list[i].type_id;

		SMW_DBG_PRINTF(DEBUG,
			       "Signature scheme (attr 0x%" PRIx64
			       ") algo_id=%d type_id=%d\n",
			       attr, *algo_id, *type_id);

		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_key_attr_to_sign_ids(smw_attr_algo_t attr,
				   enum smw_config_sign_algo_id *algo_id,
				   enum smw_config_sign_type_id *type_id,
				   bool *is_curve)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(sign_list);

	SMW_DBG_TRACE_FUNCTION_CALL;

	*algo_id = SMW_CONFIG_SIGN_ALGO_ID_INVALID;
	*type_id = SMW_CONFIG_SIGN_TYPE_ID_INVALID;

	for (; i < size; i++) {
		if (sign_list[i].class != SMW_ATTR_GET_CLASS(attr))
			continue;

		if (sign_list[i].algo != SMW_ATTR_GET_ALGO(attr))
			continue;

		*algo_id = sign_list[i].algo_id;

		if (sign_list[i].is_curve) {
			if (sign_list[i].curve != SMW_ATTR_CURVE_ANY &&
			    sign_list[i].curve != SMW_ATTR_GET_CURVE(attr))
				continue;
		} else if (sign_list[i].mode != SMW_ATTR_GET_MODE(attr)) {
			continue;
		}

		*type_id = sign_list[i].type_id;
		*is_curve = sign_list[i].is_curve;

		SMW_DBG_PRINTF(DEBUG,
			       "Attr 0x%" PRIx64 " algo_id=%d type_id=%d\n",
			       attr, *algo_id, *type_id);

		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define ASYMM_ENC_RSA_ALGO(_mode_id)                                           \
	{                                                                      \
		.algo = SMW_ATTR_ALGO_RSA, .mode = SMW_ATTR_MODE_##_mode_id,   \
		.algo_id = SMW_CONFIG_ASYMM_ENC_ALGO_ID_RSA,                   \
		.mode_id = SMW_CONFIG_ASYMM_ENC_MODE_ID_##_mode_id,            \
	}

static const struct {
	smw_attr_algo_t algo;
	smw_attr_algo_t mode;
	enum smw_config_asymm_enc_algo_id algo_id;
	enum smw_config_asymm_enc_mode_id mode_id;
} asymm_enc_list[] = { ASYMM_ENC_RSA_ALGO(OAEP), ASYMM_ENC_RSA_ALGO(PKCS1_1_5),
		       ASYMM_ENC_RSA_ALGO(NO_PAD) };

int smw_utils_asymm_enc_attr_to_ids(smw_attr_algo_t attr,
				    enum smw_config_asymm_enc_algo_id *algo_id,
				    enum smw_config_asymm_enc_mode_id *mode_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(asymm_enc_list);
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_attr_algo_t mode = SMW_ATTR_MODE_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!algo_id || !mode_id)
		goto end;

	mode = SMW_ATTR_GET_MODE(attr);
	algo = SMW_ATTR_GET_ALGO(attr);

	*algo_id = SMW_CONFIG_ASYMM_ENC_ALGO_ID_INVALID;
	*mode_id = SMW_CONFIG_ASYMM_ENC_MODE_ID_INVALID;

	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	for (; i < size; i++) {
		if (asymm_enc_list[i].algo != algo)
			continue;

		*algo_id = asymm_enc_list[i].algo_id;

		if (asymm_enc_list[i].mode != mode)
			continue;

		*mode_id = asymm_enc_list[i].mode_id;

		SMW_DBG_PRINTF(DEBUG,
			       "Asymmetric encryption scheme (attr 0x%" PRIx64
			       ") algo_id=%d mode_id=%d\n",
			       attr, *algo_id, *mode_id);

		status = SMW_STATUS_OK;
		break;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
