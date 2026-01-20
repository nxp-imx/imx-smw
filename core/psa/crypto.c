// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include "smw/names.h"
#include "smw_keymgr.h"
#include "smw_crypto.h"
#include "smw_keymgr.h"

#include "psa/crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "sign_verify.h"

#include "common.h"
#include "util_status.h"
#include "keymgr.h"

#define GET_ALGO_INFO(_algo, _array)                                           \
	({                                                                     \
		typeof(_array[0]) *_ret = NULL;                                \
		do {                                                           \
			typeof(_array[0]) *_elm = (_array);                    \
			typeof(_algo) _alg = (_algo);                          \
			while (_elm->psa_alg_id != PSA_ALG_NONE) {             \
				if (_elm->psa_alg_id == _alg) {                \
					_ret = _elm;                           \
					break;                                 \
				}                                              \
				_elm++;                                        \
			}                                                      \
		} while (0);                                                   \
		_ret;                                                          \
	})

#define AEAD_ALGO(_name)                                                       \
	{                                                                      \
		.psa_alg_id = PSA_ALG_##_name,                                 \
		.smw_mode_name = SMW_AEAD_MODE_NAME_##_name,                   \
		.tag_lengths = aead_tag_lengths_##_name,                       \
		.tag_lengths_size = ARRAY_SIZE(aead_tag_lengths_##_name)       \
	}

#define AEAD_TAG_LENGTH_DEF(_name, ...)                                        \
	static const unsigned int aead_tag_lengths_##_name[] = { __VA_ARGS__ }

AEAD_TAG_LENGTH_DEF(CCM, 4, 6, 8, 10, 12, 14, 16);
AEAD_TAG_LENGTH_DEF(CHACHA20_POLY1305, 16);
AEAD_TAG_LENGTH_DEF(GCM, 4, 8, 12, 13, 14, 15, 16);

static const struct aead_algo_info {
	psa_algorithm_t psa_alg_id;
	smw_aead_mode_t smw_mode_name;
	const unsigned int *tag_lengths;
	const size_t tag_lengths_size;
} aead_algo_info[] = { AEAD_ALGO(CCM),
		       AEAD_ALGO(CHACHA20_POLY1305),
		       AEAD_ALGO(GCM),
		       { .psa_alg_id = PSA_ALG_NONE,
			 .smw_mode_name = SMW_AEAD_MODE_NAME_NONE,
			 .tag_lengths = NULL,
			 .tag_lengths_size = 0 } };

static smw_aead_mode_t get_aead_mode_name(psa_algorithm_t alg)
{
	const struct aead_algo_info *info = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	info = GET_ALGO_INFO(alg, aead_algo_info);

	if (info)
		return info->smw_mode_name;

	return SMW_AEAD_MODE_NAME_NONE;
}

#define CIPHER_ALGO(_id, _name)                                                \
	{                                                                      \
		.psa_alg_id = PSA_ALG_##_id,                                   \
		.smw_mode_name = SMW_CIPHER_MODE_NAME_##_name                  \
	}

static const struct cipher_algo_info {
	psa_algorithm_t psa_alg_id;
	smw_cipher_mode_t smw_mode_name;
} cipher_algo_info[] = { CIPHER_ALGO(CBC_NO_PADDING, CBC),
			 CIPHER_ALGO(CFB, CFB),
			 CIPHER_ALGO(CTR, CTR),
			 CIPHER_ALGO(ECB_NO_PADDING, ECB),
			 CIPHER_ALGO(XTS, XTS),
			 CIPHER_ALGO(OFB, OFB),
			 CIPHER_ALGO(NONE, NONE) };

static smw_cipher_mode_t get_cipher_mode_name(psa_algorithm_t alg)
{
	const struct cipher_algo_info *info = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	info = GET_ALGO_INFO(alg, cipher_algo_info);

	if (info)
		return info->smw_mode_name;

	return SMW_CIPHER_MODE_NAME_NONE;
}

#define HASH_ALGO(_id, _name, _length, _block_size)                            \
	{                                                                      \
		.psa_alg_id = PSA_ALG_##_id,                                   \
		.smw_alg_name = SMW_HASH_ALGO_NAME_##_name,                    \
		.smw_alg_id = SMW_ATTR_HASH_##_name, .length = _length,        \
		.block_size = _block_size                                      \
	}

static const struct hash_algo_info {
	psa_algorithm_t psa_alg_id;
	smw_hash_algo_t smw_alg_name;
	smw_attr_algo_t smw_alg_id;
	size_t length;
	size_t block_size;
} hash_algo_info[] = { HASH_ALGO(MD5, MD5, 16, 64),
		       HASH_ALGO(SHA_1, SHA1, 20, 64),
		       HASH_ALGO(SHA_224, SHA224, 28, 64),
		       HASH_ALGO(SHA_256, SHA256, 32, 64),
		       HASH_ALGO(SHA_384, SHA384, 48, 128),
		       HASH_ALGO(SHA_512, SHA512, 64, 128),
		       HASH_ALGO(SHA3_224, SHA3_224, 28, 64),
		       HASH_ALGO(SHA3_256, SHA3_256, 32, 64),
		       HASH_ALGO(SHA3_384, SHA3_384, 48, 128),
		       HASH_ALGO(SHA3_512, SHA3_512, 64, 128),
		       HASH_ALGO(SM3, SM3, 32, 64),
		       HASH_ALGO(SHAKE256_512, SHAKE256, 64, 136),
		       { .psa_alg_id = PSA_ALG_NONE,
			 .smw_alg_name = SMW_HASH_ALGO_NAME_NONE,
			 .smw_alg_id = SMW_ATTR_HASH_ANY,
			 .length = 0,
			 .block_size = 0 } };

static const struct hash_algo_info *get_hash_algo_info(psa_algorithm_t alg)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return GET_ALGO_INFO(alg, hash_algo_info);
}

smw_hash_algo_t get_hash_algo_name(psa_algorithm_t alg)
{
	const struct hash_algo_info *info = get_hash_algo_info(alg);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return SMW_HASH_ALGO_NAME_NONE;

	return info->smw_alg_name;
}

smw_attr_algo_t get_hash_algo_attr(psa_algorithm_t alg)
{
	const struct hash_algo_info *info = get_hash_algo_info(alg);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return SMW_ATTR_HASH_NONE;

	return info->smw_alg_id;
}

static const struct mac_algo_info {
	psa_algorithm_t psa_alg_id;
	smw_mac_algo_t smw_alg_name;
} mac_algo_info[] = {
	{ .psa_alg_id = PSA_ALG_HMAC_BASE,
	  .smw_alg_name = SMW_MAC_ALGO_NAME_HMAC },
	{ .psa_alg_id = PSA_ALG_HMAC_BASE | PSA_ALG_MAC_TRUNCATION_MASK,
	  .smw_alg_name = SMW_MAC_ALGO_NAME_HMAC_TRUNCATED },
	{ .psa_alg_id = PSA_ALG_CMAC, .smw_alg_name = SMW_MAC_ALGO_NAME_CMAC },
	{ .psa_alg_id = PSA_ALG_CMAC | PSA_ALG_MAC_TRUNCATION_MASK,
	  .smw_alg_name = SMW_MAC_ALGO_NAME_CMAC_TRUNCATED },
	{ .psa_alg_id = PSA_ALG_NONE, .smw_alg_name = SMW_MAC_ALGO_NAME_NONE }
};

static smw_mac_algo_t get_mac_algo_name(psa_algorithm_t alg)
{
	const struct mac_algo_info *info = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (alg & PSA_ALG_MAC_TRUNCATION_MASK)
		alg |= PSA_ALG_MAC_TRUNCATION_MASK;

	info = GET_ALGO_INFO(alg & ~(PSA_ALG_HASH_MASK |
				     PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG),
			     mac_algo_info);

	if (info)
		return info->smw_alg_name;

	return SMW_MAC_ALGO_NAME_NONE;
}

static bool check_aead_tag_length(psa_algorithm_t alg, unsigned int tag_length)
{
	const struct aead_algo_info *info = NULL;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	info = GET_ALGO_INFO(alg, aead_algo_info);

	if (!info)
		return false;

	for (i = 0; i < info->tag_lengths_size; i++) {
		if (tag_length == info->tag_lengths[i])
			return true;
	}

	return false;
}

static bool is_psa_subsystem_ele(void)
{
	smw_subsystem_t subsystem_name = SMW_SUBSYSTEM_NAME_NONE;

	subsystem_name = get_psa_default_subsystem();

	return (subsystem_name == SMW_SUBSYSTEM_NAME_ELE);
}

static psa_status_t
set_aead_common_params(psa_key_id_t key, psa_algorithm_t alg,
		       const uint8_t *nonce, size_t nonce_length,
		       const uint8_t *additional_data,
		       size_t additional_data_length, const uint8_t *input,
		       size_t input_length, uint8_t *output, size_t output_size,
		       struct smw_aead_args *args, smw_aead_op_type_t op_name)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_aead_init_args *init = args->init;
	struct smw_aead_aad_args *aad = args->aad;
	struct smw_aead_final_args *final = args->final;
	struct smw_aead_data_args *data = final->data;
	smw_aead_mode_t mode_name = SMW_AEAD_MODE_NAME_NONE;
	unsigned int tag_length = 0;
	unsigned int min_output_size = 0;
	psa_algorithm_t psa_base_alg = PSA_ALG_NONE;

	if (!PSA_ALG_IS_AEAD(alg) || !input || !input_length || !output ||
	    !output_size || !nonce || !nonce_length ||
	    op_name == SMW_AEAD_OP_TYPE_NAME_NONE)
		return PSA_ERROR_INVALID_ARGUMENT;

	init->key_desc->id = key;
	status = smw_get_key_type_name(init->key_desc);
	if (status != SMW_STATUS_OK)
		return util_smw_to_psa_status(status);

	tag_length = PSA_ALG_AEAD_TAG_LENGTH(alg);
	if (!tag_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (nonce_length > PSA_AEAD_NONCE_MAX_SIZE)
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_base_alg = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(alg);

	if (!check_aead_tag_length(psa_base_alg, tag_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	switch (psa_base_alg) {
	case PSA_ALG_CCM:
		if (nonce_length < 7 || nonce_length > 13)
			return PSA_ERROR_INVALID_ARGUMENT;
		if (is_psa_subsystem_ele() && nonce_length != 12)
			return PSA_ERROR_INVALID_ARGUMENT;
		break;

	case PSA_ALG_GCM:
		if (is_psa_subsystem_ele() && nonce_length != 12)
			return PSA_ERROR_INVALID_ARGUMENT;
		break;

	case PSA_ALG_CHACHA20_POLY1305:
		if (nonce_length != 8 && nonce_length != 12)
			return PSA_ERROR_INVALID_ARGUMENT;
		break;
	}

	mode_name = get_aead_mode_name(psa_base_alg);
	if (mode_name == SMW_AEAD_MODE_NAME_NONE)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (op_name == SMW_AEAD_OP_TYPE_NAME_ENCRYPT) {
		if (SET_OVERFLOW(PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg,
							      input_length),
				 min_output_size))
			return PSA_ERROR_INVALID_ARGUMENT;
	} else if (op_name == SMW_AEAD_OP_TYPE_NAME_DECRYPT) {
		if (input_length + 1 < tag_length)
			return PSA_ERROR_BUFFER_TOO_SMALL;

		if (SET_OVERFLOW(PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg,
							      input_length),
				 min_output_size))
			return PSA_ERROR_INVALID_ARGUMENT;
	} else {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	if (output_size < min_output_size)
		return PSA_ERROR_BUFFER_TOO_SMALL;

	init->mode_name = mode_name;
	init->plaintext_length = input_length;
	init->user_iv = (unsigned char *)nonce;
	init->user_iv_length = nonce_length;
	init->iv_length = nonce_length;
	init->op_type_name = op_name;

	data->input = (unsigned char *)input;
	data->input_length = input_length;
	data->output = output;
	data->output_length = output_size;

	final->tag = NULL;

	final->tag_length = tag_length;
	final->op_type_name = op_name;

	aad->data = (unsigned char *)additional_data;

	if (SET_OVERFLOW(additional_data_length, aad->data_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	return PSA_SUCCESS;
}

static psa_status_t
set_aead_encrypt_params(psa_key_id_t key, psa_algorithm_t alg,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length, const uint8_t *input,
			size_t input_length, uint8_t *output,
			size_t output_size, struct smw_aead_args *args)
{
	psa_status_t status;

	status =
		set_aead_common_params(key, alg, nonce, nonce_length,
				       additional_data, additional_data_length,
				       input, input_length, output, output_size,
				       args, SMW_AEAD_OP_TYPE_NAME_ENCRYPT);
	if (status != PSA_SUCCESS)
		return status;

	if (SET_OVERFLOW(nonce_length, args->final->output_iv_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	args->final->output_iv = SMW_UTILS_CALLOC(1, nonce_length);
	if (!args->final->output_iv)
		return PSA_ERROR_INSUFFICIENT_MEMORY;

	return PSA_SUCCESS;
}

static psa_status_t
set_aead_decrypt_params(psa_key_id_t key, psa_algorithm_t alg,
			const uint8_t *nonce, size_t nonce_length,
			const uint8_t *additional_data,
			size_t additional_data_length, const uint8_t *input,
			size_t input_length, uint8_t *output,
			size_t output_size, struct smw_aead_args *args)
{
	psa_status_t status;

	status =
		set_aead_common_params(key, alg, nonce, nonce_length,
				       additional_data, additional_data_length,
				       input, input_length, output, output_size,
				       args, SMW_AEAD_OP_TYPE_NAME_DECRYPT);
	if (status != PSA_SUCCESS)
		return status;

	return PSA_SUCCESS;
}

__export size_t psa_cipher_encrypt_output_size(psa_key_type_t key_type,
					       psa_algorithm_t alg,
					       size_t input_length)
{
	size_t iv_length = 0;
	size_t size = 0;

	if (PSA_ALG_IS_CIPHER(alg)) {
		iv_length = psa_cipher_iv_length(key_type, alg);
		if (ADD_OVERFLOW(iv_length, input_length, &size))
			size = 0;
	}

	return size;
}

__export size_t psa_cipher_iv_length(psa_key_type_t key_type,
				     psa_algorithm_t alg)
{
	size_t iv_length = PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type);

	if (iv_length > 1 &&
	    (alg == PSA_ALG_CTR || alg == PSA_ALG_CFB || alg == PSA_ALG_OFB ||
	     alg == PSA_ALG_XTS || alg == PSA_ALG_CBC_NO_PADDING ||
	     alg == PSA_ALG_CBC_PKCS7))
		return iv_length;
	else if (key_type == PSA_KEY_TYPE_CHACHA20 &&
		 alg == PSA_ALG_STREAM_CIPHER)
		return 12;

	return 0;
}

__export size_t psa_hash_block_length(psa_algorithm_t alg)
{
	const struct hash_algo_info *info = get_hash_algo_info(alg);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return 0;

	return info->block_size;
}

__export size_t psa_hash_length(psa_algorithm_t alg)
{
	const struct hash_algo_info *info = get_hash_algo_info(alg);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return 0;

	return info->length;
}

static psa_status_t set_signature_attributes(psa_algorithm_t alg, bool hashed,
					     smw_attr_algo_t *sign_algo)
{
	const struct hash_algo_info *info =
		get_hash_algo_info(PSA_ALG_GET_HASH(alg));
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_attr_algo_t mode = SMW_ATTR_MODE_NONE;
	smw_attr_algo_t hash = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t curve = SMW_ATTR_CURVE_NONE;
	smw_attr_algo_t eddsa_param = SMW_ATTR_SIGN_PARAM_EDDSA_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (info)
		hash = info->smw_alg_id;

	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
		algo = SMW_ATTR_ALGO_RSA;
		mode = SMW_ATTR_MODE_PKCS1_1_5;
	} else if (PSA_ALG_IS_RSA_PSS(alg)) {
		algo = SMW_ATTR_ALGO_RSA;
		mode = SMW_ATTR_MODE_PSS;
	} else if (PSA_ALG_IS_ECDSA(alg)) {
		algo = SMW_ATTR_ALGO_ECDSA;
		curve = SMW_ATTR_MODE_ANY;
	} else if (PSA_ALG_IS_HASH_EDDSA(alg) || alg == PSA_ALG_PURE_EDDSA) {
		algo = SMW_ATTR_ALGO_EDDSA;
		hash = SMW_ATTR_HASH_NONE;

		if (alg == PSA_ALG_ED448PH) {
			curve = SMW_ATTR_CURVE_ED448;
			eddsa_param = SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED;
		} else if (alg == PSA_ALG_ED25519PH) {
			curve = SMW_ATTR_CURVE_ED25519;
			eddsa_param = SMW_ATTR_SIGN_PARAM_EDDSA_PREHASHED;
		} else if (alg == PSA_ALG_PURE_EDDSA) {
			curve = SMW_ATTR_CURVE_ANY;
		} else {
			return PSA_ERROR_INVALID_ARGUMENT;
		}
	}

	if (algo == SMW_ATTR_ALGO_RSA)
		*sign_algo =
			SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(mode, hash, 0);
	else if (algo == SMW_ATTR_ALGO_ECDSA)
		*sign_algo =
			SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(curve, hash);
	else if (algo == SMW_ATTR_ALGO_EDDSA)
		*sign_algo =
			SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA(curve, hash,
								 eddsa_param);

	if (hashed)
		*sign_algo = SMW_ATTR_SET_MSG_HASHED(*sign_algo);

	return PSA_SUCCESS;
}

__export psa_status_t psa_aead_abort(psa_aead_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_aead_decrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
		 size_t nonce_length, const uint8_t *additional_data,
		 size_t additional_data_length, const uint8_t *ciphertext,
		 size_t ciphertext_length, uint8_t *plaintext,
		 size_t plaintext_size, size_t *plaintext_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_aead_args oneshot_args = { 0 };
	struct smw_aead_aad_args aad = { 0 };
	struct smw_aead_init_args init = { 0 };
	struct smw_aead_final_args final = { 0 };
	struct smw_aead_data_args data = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!plaintext_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	init.key_desc = &key_desc;
	final.data = &data;

	oneshot_args.aad = &aad;
	oneshot_args.init = &init;
	oneshot_args.final = &final;

	psa_status = set_aead_decrypt_params(key, alg, nonce, nonce_length,
					     additional_data,
					     additional_data_length, ciphertext,
					     ciphertext_length, plaintext,
					     plaintext_size, &oneshot_args);

	if (psa_status != PSA_SUCCESS)
		goto end;

	if (data.output_length == 0)
		goto end;

	psa_status =
		call_smw_api((enum smw_status_code(*)(void *))smw_aead,
			     &oneshot_args, &oneshot_args.init->subsystem_name);

	if (psa_status != PSA_SUCCESS &&
	    psa_status != PSA_ERROR_BUFFER_TOO_SMALL)
		goto end;

	*plaintext_length = data.output_length;

end:
	return psa_status;
}

__export psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t *operation,
					     psa_key_id_t key,
					     psa_algorithm_t alg)
{
	(void)operation;
	(void)key;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_aead_encrypt(psa_key_id_t key, psa_algorithm_t alg, const uint8_t *nonce,
		 size_t nonce_length, const uint8_t *additional_data,
		 size_t additional_data_length, const uint8_t *plaintext,
		 size_t plaintext_length, uint8_t *ciphertext,
		 size_t ciphertext_size, size_t *ciphertext_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_aead_args oneshot_args = { 0 };
	struct smw_aead_aad_args aad = { 0 };
	struct smw_aead_init_args init = { 0 };
	struct smw_aead_final_args final = { 0 };
	struct smw_aead_data_args data = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!ciphertext_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	init.key_desc = &key_desc;
	final.data = &data;

	oneshot_args.aad = &aad;
	oneshot_args.init = &init;
	oneshot_args.final = &final;

	psa_status =
		set_aead_encrypt_params(key, alg, nonce, nonce_length,
					additional_data, additional_data_length,
					plaintext, plaintext_length, ciphertext,
					ciphertext_size, &oneshot_args);

	if (psa_status != PSA_SUCCESS)
		goto end;

	if (!data.output_length)
		goto end;

	psa_status =
		call_smw_api((enum smw_status_code(*)(void *))smw_aead,
			     &oneshot_args, &oneshot_args.init->subsystem_name);

	if (psa_status != PSA_SUCCESS &&
	    psa_status != PSA_ERROR_BUFFER_TOO_SMALL)
		goto end;

	*ciphertext_length = data.output_length;

end:
	if (oneshot_args.final->output_iv)
		SMW_UTILS_FREE(oneshot_args.final->output_iv);

	return psa_status;
}

__export psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t *operation,
					     psa_key_id_t key,
					     psa_algorithm_t alg)
{
	(void)operation;
	(void)key;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_finish(psa_aead_operation_t *operation,
				      uint8_t *ciphertext,
				      size_t ciphertext_size,
				      size_t *ciphertext_length, uint8_t *tag,
				      size_t tag_size, size_t *tag_length)
{
	(void)operation;
	(void)ciphertext;
	(void)ciphertext_size;
	(void)ciphertext_length;
	(void)tag;
	(void)tag_size;
	(void)tag_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_generate_nonce(psa_aead_operation_t *operation,
					      uint8_t *nonce, size_t nonce_size,
					      size_t *nonce_length)
{
	(void)operation;
	(void)nonce;
	(void)nonce_size;
	(void)nonce_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_set_lengths(psa_aead_operation_t *operation,
					   size_t ad_length,
					   size_t plaintext_length)
{
	(void)operation;
	(void)ad_length;
	(void)plaintext_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_set_nonce(psa_aead_operation_t *operation,
					 const uint8_t *nonce,
					 size_t nonce_length)
{
	(void)operation;
	(void)nonce;
	(void)nonce_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_update(psa_aead_operation_t *operation,
				      const uint8_t *input, size_t input_length,
				      uint8_t *output, size_t output_size,
				      size_t *output_length)
{
	(void)operation;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_update_ad(psa_aead_operation_t *operation,
					 const uint8_t *input,
					 size_t input_length)
{
	(void)operation;
	(void)input;
	(void)input_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_aead_verify(psa_aead_operation_t *operation,
				      uint8_t *plaintext, size_t plaintext_size,
				      size_t *plaintext_length,
				      const uint8_t *tag, size_t tag_length)
{
	(void)operation;
	(void)plaintext;
	(void)plaintext_size;
	(void)plaintext_length;
	(void)tag;
	(void)tag_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_asymmetric_decrypt(psa_key_id_t key, psa_algorithm_t alg,
		       const uint8_t *input, size_t input_length,
		       const uint8_t *salt, size_t salt_length, uint8_t *output,
		       size_t output_size, size_t *output_length)
{
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)salt;
	(void)salt_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_asymmetric_encrypt(psa_key_id_t key, psa_algorithm_t alg,
		       const uint8_t *input, size_t input_length,
		       const uint8_t *salt, size_t salt_length, uint8_t *output,
		       size_t output_size, size_t *output_length)
{
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)salt;
	(void)salt_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_cipher_abort(psa_cipher_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t set_cipher_args(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    uint8_t *output, size_t output_size,
				    size_t *output_length,
				    smw_cipher_op_type_t op_type_name,
				    struct smw_key_descriptor *key_descriptor,
				    struct smw_cipher_args *args)
{
	psa_status_t psa_status = PSA_SUCCESS;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_cipher_init_args *init = &args->init;
	struct smw_cipher_data_args *data = &args->data;
	psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
	unsigned char *iv = NULL;

	if (!PSA_ALG_IS_CIPHER(alg) || !input || !input_length || !output ||
	    !output_size || !output_length ||
	    op_type_name == SMW_CIPHER_OP_TYPE_NAME_NONE)
		return PSA_ERROR_INVALID_ARGUMENT;

	key_descriptor->id = key;

	status = smw_get_key_type_name(key_descriptor);
	if (status != SMW_STATUS_OK)
		return util_smw_to_psa_status(status);

	key_type = get_cipher_psa_key_type(key_descriptor->type_name);
	if (key_type == PSA_KEY_TYPE_NONE)
		return PSA_ERROR_INVALID_ARGUMENT;

	if ((alg == PSA_ALG_CBC_NO_PADDING || alg == PSA_ALG_ECB_NO_PADDING) &&
	    input_length % PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type))
		return PSA_ERROR_INVALID_ARGUMENT;

	init->mode_name = get_cipher_mode_name(alg);
	if (init->mode_name == SMW_CIPHER_MODE_NAME_NONE)
		return PSA_ERROR_NOT_SUPPORTED;

	if (SET_OVERFLOW(PSA_CIPHER_IV_LENGTH(key_type, alg), init->iv_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (op_type_name == SMW_CIPHER_OP_TYPE_NAME_ENCRYPT) {
		if (output_size <= init->iv_length)
			return PSA_ERROR_INVALID_ARGUMENT;

		if (init->iv_length) {
			iv = SMW_UTILS_MALLOC(init->iv_length);
			if (!iv)
				return PSA_ERROR_INSUFFICIENT_MEMORY;

			psa_status = psa_generate_random(iv, init->iv_length);
			if (psa_status != PSA_SUCCESS)
				goto end;
		}
		init->iv = iv;

		data->input = (unsigned char *)input;
		data->input_length = input_length;

		data->output = output + init->iv_length;
		data->output_length = output_size - init->iv_length;
	} else if (op_type_name == SMW_CIPHER_OP_TYPE_NAME_DECRYPT) {
		if (input_length < init->iv_length)
			return PSA_ERROR_INVALID_ARGUMENT;

		init->iv = (unsigned char *)input;

		data->input = (unsigned char *)input + init->iv_length;
		data->input_length = input_length - init->iv_length;

		data->output = output;
		data->output_length = output_size;

		if (!data->input_length)
			return PSA_SUCCESS;
	} else {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	init->nb_keys = 1;
	init->keys_desc =
		SMW_UTILS_MALLOC(init->nb_keys * sizeof(init->keys_desc[0]));
	if (!init->keys_desc) {
		psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
		goto end;
	}

	init->keys_desc[0] = key_descriptor;

	init->op_type_name = op_type_name;

end:
	if (psa_status != PSA_SUCCESS)
		if (iv)
			SMW_UTILS_FREE(iv);

	return psa_status;
}

__export psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg,
					 const uint8_t *input,
					 size_t input_length, uint8_t *output,
					 size_t output_size,
					 size_t *output_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_cipher_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	psa_status = set_cipher_args(key, alg, input, input_length, output,
				     output_size, output_length,
				     SMW_CIPHER_OP_TYPE_NAME_DECRYPT,
				     &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	if (!args.data.input_length) {
		*output_length = 0;
		return PSA_SUCCESS;
	}

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_cipher,
				  &args, &args.init.subsystem_name);

	if (psa_status == PSA_SUCCESS)
		*output_length = args.data.output_length;

	if (args.init.keys_desc)
		SMW_UTILS_FREE(args.init.keys_desc);

	return psa_status;
}

__export psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t *operation,
					       psa_key_id_t key,
					       psa_algorithm_t alg)
{
	(void)operation;
	(void)key;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_cipher_encrypt(psa_key_id_t key, psa_algorithm_t alg,
					 const uint8_t *input,
					 size_t input_length, uint8_t *output,
					 size_t output_size,
					 size_t *output_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_cipher_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	psa_status = set_cipher_args(key, alg, input, input_length, output,
				     output_size, output_length,
				     SMW_CIPHER_OP_TYPE_NAME_ENCRYPT,
				     &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		goto end;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_cipher,
				  &args, &args.init.subsystem_name);

	if (psa_status == PSA_SUCCESS) {
		if (ADD_OVERFLOW(args.data.output_length, args.init.iv_length,
				 output_length))
			psa_status = PSA_ERROR_DATA_CORRUPT;

		if (args.init.iv_length)
			SMW_UTILS_MEMCPY(output, args.init.iv,
					 args.init.iv_length);
	}

end:
	if (args.init.iv)
		SMW_UTILS_FREE(args.init.iv);

	if (args.init.keys_desc)
		SMW_UTILS_FREE(args.init.keys_desc);

	return psa_status;
}

__export psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t *operation,
					       psa_key_id_t key,
					       psa_algorithm_t alg)
{
	(void)operation;
	(void)key;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_cipher_finish(psa_cipher_operation_t *operation,
					uint8_t *output, size_t output_size,
					size_t *output_length)
{
	(void)operation;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t *operation,
					     uint8_t *iv, size_t iv_size,
					     size_t *iv_length)
{
	(void)operation;
	(void)iv;
	(void)iv_size;
	(void)iv_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_cipher_set_iv(psa_cipher_operation_t *operation,
					const uint8_t *iv, size_t iv_length)
{
	(void)operation;
	(void)iv;
	(void)iv_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_cipher_update(psa_cipher_operation_t *operation,
					const uint8_t *input,
					size_t input_length, uint8_t *output,
					size_t output_size,
					size_t *output_length)
{
	(void)operation;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_crypto_init(void)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_GENERIC_ERROR;

	return PSA_SUCCESS;
}

__export psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
	struct smw_rng_args args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	args.output = output;

	if (SET_OVERFLOW(output_size, args.output_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (output_size)
		return call_smw_api((enum smw_status_code(*)(void *))smw_rng,
				    &args, &args.subsystem_name);

	return PSA_SUCCESS;
}

__export psa_status_t psa_hash_abort(psa_hash_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_hash_clone(const psa_hash_operation_t *source_operation,
	       psa_hash_operation_t *target_operation)
{
	(void)source_operation;
	(void)target_operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_compare(psa_algorithm_t alg,
				       const uint8_t *input,
				       size_t input_length, const uint8_t *hash,
				       size_t hash_length)
{
	psa_status_t psa_status = PSA_SUCCESS;
	uint8_t hash_computed[PSA_HASH_MAX_SIZE] = { 0 };
	size_t hash_computed_length = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	psa_status =
		psa_hash_compute(alg, input, input_length, hash_computed,
				 sizeof(hash_computed), &hash_computed_length);

	if (psa_status != PSA_SUCCESS)
		return psa_status;

	if (hash_computed_length != hash_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	for (; i < hash_length; i++)
		if (hash[i] != hash_computed[i])
			return PSA_ERROR_INVALID_SIGNATURE;

	return PSA_SUCCESS;
}

__export psa_status_t psa_hash_compute(psa_algorithm_t alg,
				       const uint8_t *input,
				       size_t input_length, uint8_t *hash,
				       size_t hash_size, size_t *hash_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_hash_args args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	args.algo_name = get_hash_algo_name(alg);
	if (args.algo_name == SMW_HASH_ALGO_NAME_NONE)
		return PSA_ERROR_NOT_SUPPORTED;

	args.input = (unsigned char *)input;

	if (SET_OVERFLOW(input_length, args.input_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	args.output = hash;

	if (SET_OVERFLOW(hash_size, args.output_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_hash,
				  &args, &args.subsystem_name);

	*hash_length = args.output_length;

	return psa_status;
}

__export psa_status_t psa_hash_finish(psa_hash_operation_t *operation,
				      uint8_t *hash, size_t hash_size,
				      size_t *hash_length)
{
	(void)operation;
	(void)hash;
	(void)hash_size;
	(void)hash_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_resume(psa_hash_operation_t *operation,
				      const uint8_t *hash_state,
				      size_t hash_state_length)
{
	(void)operation;
	(void)hash_state;
	(void)hash_state_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_setup(psa_hash_operation_t *operation,
				     psa_algorithm_t alg)
{
	(void)operation;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_suspend(psa_hash_operation_t *operation,
				       uint8_t *hash_state,
				       size_t hash_state_size,
				       size_t *hash_state_length)
{
	(void)operation;
	(void)hash_state;
	(void)hash_state_size;
	(void)hash_state_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_update(psa_hash_operation_t *operation,
				      const uint8_t *input, size_t input_length)
{
	(void)operation;
	(void)input;
	(void)input_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_verify(psa_hash_operation_t *operation,
				      const uint8_t *hash, size_t hash_length)
{
	(void)operation;
	(void)hash;
	(void)hash_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_mac_abort(psa_mac_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_mac_compute(psa_key_id_t key, psa_algorithm_t alg,
				      const uint8_t *input, size_t input_length,
				      uint8_t *mac, size_t mac_size,
				      size_t *mac_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;

	struct smw_mac_args op_args = { 0 };
	struct smw_key_descriptor op_key = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!mac_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	op_key.id = key;
	op_args.key_descriptor = &op_key;
	op_args.algo_name = get_mac_algo_name(alg);
	op_args.hash_name = get_hash_algo_name(PSA_ALG_GET_HASH(alg));
	op_args.input = (unsigned char *)input;

	if (SET_OVERFLOW(input_length, op_args.input_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	op_args.mac = mac;

	if (SET_OVERFLOW(mac_size, op_args.mac_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_mac,
				  &op_args, &op_args.subsystem_name);

	if ((psa_status == PSA_SUCCESS ||
	     psa_status == PSA_ERROR_BUFFER_TOO_SMALL) &&
	    mac_length)
		*mac_length = op_args.mac_length;

	return psa_status;
}

__export psa_status_t psa_mac_sign_finish(psa_mac_operation_t *operation,
					  uint8_t *mac, size_t mac_size,
					  size_t *mac_length)
{
	(void)operation;
	(void)mac;
	(void)mac_size;
	(void)mac_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_mac_sign_setup(psa_mac_operation_t *operation,
					 psa_key_id_t key, psa_algorithm_t alg)
{
	(void)operation;
	(void)key;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_mac_update(psa_mac_operation_t *operation,
				     const uint8_t *input, size_t input_length)
{
	(void)operation;
	(void)input;
	(void)input_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_mac_verify(psa_key_id_t key, psa_algorithm_t alg,
				     const uint8_t *input, size_t input_length,
				     const uint8_t *mac, size_t mac_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;

	struct smw_mac_args op_args = { 0 };
	struct smw_key_descriptor op_key = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!mac_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	op_key.id = key;
	op_args.key_descriptor = &op_key;
	op_args.algo_name = get_mac_algo_name(alg);
	op_args.hash_name = get_hash_algo_name(PSA_ALG_GET_HASH(alg));
	op_args.input = (unsigned char *)input;

	if (SET_OVERFLOW(input_length, op_args.input_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	op_args.mac = (unsigned char *)mac;

	if (SET_OVERFLOW(mac_length, op_args.mac_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status =
		call_smw_api((enum smw_status_code(*)(void *))smw_mac_verify,
			     &op_args, &op_args.subsystem_name);

	return psa_status;
}

__export psa_status_t psa_mac_verify_finish(psa_mac_operation_t *operation,
					    const uint8_t *mac,
					    size_t mac_length)
{
	(void)operation;
	(void)mac;
	(void)mac_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_mac_verify_setup(psa_mac_operation_t *operation,
					   psa_key_id_t key,
					   psa_algorithm_t alg)
{
	(void)operation;
	(void)key;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_purge_key(psa_key_id_t key)
{
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_agreement(psa_key_id_t private_key,
			       const uint8_t *peer_key, size_t peer_key_length,
			       psa_algorithm_t alg,
			       const psa_key_attributes_t *attributes,
			       psa_key_id_t *key)
{
	(void)private_key;
	(void)peer_key;
	(void)peer_key_length;
	(void)alg;
	(void)attributes;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
					    psa_key_id_t private_key,
					    const uint8_t *peer_key,
					    size_t peer_key_length,
					    uint8_t *output, size_t output_size,
					    size_t *output_length)
{
	(void)alg;
	(void)private_key;
	(void)peer_key;
	(void)peer_key_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t
set_sign_verify_args(psa_key_id_t key, psa_algorithm_t alg,
		     const uint8_t *message, size_t message_length,
		     uint8_t *signature, size_t signature_size, bool hashed,
		     struct smw_key_descriptor *key_descriptor,
		     struct smw_sign_verify_args *args)
{
	enum smw_status_code status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_descriptor->id = key;

	status = smw_get_key_type_name(key_descriptor);
	if (status != SMW_STATUS_OK)
		return util_smw_to_psa_status(status);

	if ((!hashed && !PSA_ALG_IS_SIGN_MESSAGE(alg)) ||
	    (hashed && !PSA_ALG_IS_SIGN_HASH(alg)))
		return PSA_ERROR_INVALID_ARGUMENT;

	args->key_descriptor = key_descriptor;
	args->message = (unsigned char *)message;

	if (SET_OVERFLOW(message_length, args->message_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	args->signature = signature;

	if (SET_OVERFLOW(signature_size, args->signature_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	return set_signature_attributes(alg, hashed, &args->sign_algo);
}

static psa_status_t get_sign_hash_algo(psa_algorithm_t alg,
				       psa_algorithm_t *hash_algo)
{
	if (alg == PSA_ALG_ED25519PH)
		*hash_algo = PSA_ALG_SHA_512;
	else if (alg == PSA_ALG_ED448PH)
		*hash_algo = PSA_ALG_SHAKE256_512;
	else
		return PSA_ERROR_INVALID_ARGUMENT;

	return PSA_SUCCESS;
}

static psa_status_t sign_common(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *message, size_t message_length,
				uint8_t *signature, size_t signature_size,
				size_t *signature_length, bool hashed)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_sign_verify_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	size_t computed_digest_length = 0;
	uint8_t digest[PSA_HASH_MAX_SIZE] = { 0 };
	psa_algorithm_t hash_algo = PSA_ALG_NONE;
	const uint8_t *input = NULL;
	size_t input_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	/*
	 * Input message should be pre-hashed only when using HashEdDSA
	 * algo with psa_sign_message() or psa_verify_message().
	 */
	if (!hashed && PSA_ALG_IS_HASH_EDDSA(alg)) {
		psa_status = get_sign_hash_algo(alg, &hash_algo);
		if (psa_status != PSA_SUCCESS)
			return psa_status;

		psa_status =
			psa_hash_compute(hash_algo, message, message_length,
					 digest, sizeof(digest),
					 &computed_digest_length);
		if (psa_status != PSA_SUCCESS)
			return psa_status;

		input = digest;
		input_length = computed_digest_length;
	} else {
		input = message;
		input_length = message_length;
	}

	psa_status = set_sign_verify_args(key, alg, input, input_length,
					  signature, signature_size, hashed,
					  &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_sign,
				  &args, &args.subsystem_name);

	if (psa_status == PSA_SUCCESS && signature_length)
		*signature_length = args.signature_length;

	return psa_status;
}

__export psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *hash, size_t hash_length,
				    uint8_t *signature, size_t signature_size,
				    size_t *signature_length)
{
	return sign_common(key, alg, hash, hash_length, signature,
			   signature_size, signature_length, true);
}

__export psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg,
				       const uint8_t *input,
				       size_t input_length, uint8_t *signature,
				       size_t signature_size,
				       size_t *signature_length)
{
	return sign_common(key, alg, input, input_length, signature,
			   signature_size, signature_length, false);
}

static psa_status_t verify_common(psa_key_id_t key, psa_algorithm_t alg,
				  const uint8_t *message, size_t message_length,
				  const uint8_t *signature,
				  size_t signature_length, bool hashed)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_sign_verify_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	size_t computed_digest_length = 0;
	uint8_t digest[PSA_HASH_MAX_SIZE] = { 0 };
	psa_algorithm_t hash_algo = PSA_ALG_NONE;
	const uint8_t *input = NULL;
	size_t input_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!signature || !signature_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	if (!hashed && PSA_ALG_IS_HASH_EDDSA(alg)) {
		psa_status = get_sign_hash_algo(alg, &hash_algo);
		if (psa_status != PSA_SUCCESS)
			return psa_status;

		psa_status =
			psa_hash_compute(hash_algo, message, message_length,
					 digest, sizeof(digest),
					 &computed_digest_length);
		if (psa_status != PSA_SUCCESS)
			return psa_status;

		input = digest;
		input_length = computed_digest_length;

	} else {
		input = message;
		input_length = message_length;
	}

	psa_status =
		set_sign_verify_args(key, alg, input, input_length,
				     (uint8_t *)signature, signature_length,
				     hashed, &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_verify,
				  &args, &args.subsystem_name);

	return psa_status;
}

__export psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
				      const uint8_t *hash, size_t hash_length,
				      const uint8_t *signature,
				      size_t signature_length)
{
	return verify_common(key, alg, hash, hash_length, signature,
			     signature_length, true);
}

__export psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg,
					 const uint8_t *input,
					 size_t input_length,
					 const uint8_t *signature,
					 size_t signature_length)
{
	return verify_common(key, alg, input, input_length, signature,
			     signature_length, false);
}

__export psa_algorithm_t
psa_pake_cs_get_algorithm(const psa_pake_cipher_suite_t *cipher_suite)
{
	(void)cipher_suite;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ALG_NONE;
}

__export void psa_pake_cs_set_algorithm(psa_pake_cipher_suite_t *cipher_suite,
					psa_algorithm_t alg)
{
	(void)cipher_suite;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

__export psa_pake_primitive_t
psa_pake_cs_get_primitive(const psa_pake_cipher_suite_t *cipher_suite)
{
	(void)cipher_suite;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return 0;
}

__export void psa_pake_cs_set_primitive(psa_pake_cipher_suite_t *cipher_suite,
					psa_pake_primitive_t primitive)
{
	(void)cipher_suite;
	(void)primitive;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

__export uint32_t
psa_pake_cs_get_key_confirmation(const psa_pake_cipher_suite_t *cipher_suite)
{
	(void)cipher_suite;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_PAKE_UNCONFIRMED_KEY;
}

__export void
psa_pake_cs_set_key_confirmation(psa_pake_cipher_suite_t *cipher_suite,
				 uint32_t key_confirmation)
{
	(void)cipher_suite;
	(void)key_confirmation;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

__export psa_status_t psa_pake_setup(psa_pake_operation_t *operation,
				     psa_key_id_t password_key,
				     const psa_pake_cipher_suite_t *cipher_suite)
{
	(void)operation;
	(void)password_key;
	(void)cipher_suite;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_pake_set_role(psa_pake_operation_t *operation,
					psa_pake_role_t role)
{
	(void)operation;
	(void)role;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_pake_set_user(psa_pake_operation_t *operation,
					const uint8_t *user_id,
					size_t user_id_len)
{
	(void)operation;
	(void)user_id;
	(void)user_id_len;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_pake_set_peer(psa_pake_operation_t *operation,
					const uint8_t *peer_id,
					size_t peer_id_len)
{
	(void)operation;
	(void)peer_id;
	(void)peer_id_len;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_pake_output(psa_pake_operation_t *operation,
				      psa_pake_step_t step, uint8_t *output,
				      size_t output_size, size_t *output_length)
{
	(void)operation;
	(void)step;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_pake_input(psa_pake_operation_t *operation,
				     psa_pake_step_t step, const uint8_t *input,
				     size_t input_length)
{
	(void)operation;
	(void)step;
	(void)input;
	(void)input_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_pake_get_shared_key(psa_pake_operation_t *operation,
			const psa_key_attributes_t *attributes,
			psa_key_id_t *key)
{
	(void)operation;
	(void)attributes;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_pake_abort(psa_pake_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}
