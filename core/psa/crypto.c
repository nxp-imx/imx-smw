// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_keymgr.h"
#include "smw_crypto.h"
#include "smw_keymgr.h"

#include "psa/crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "tlv.h"
#include "sign_verify.h"

#include "common.h"
#include "util_status.h"
#include "keymgr.h"

#define CIPHER_ALGO(_id, _name)                                                \
	{                                                                      \
		.psa_alg_id = PSA_ALG_##_id, .smw_mode_name = _name            \
	}

static const struct cipher_algo_info {
	psa_algorithm_t psa_alg_id;
	smw_cipher_mode_t smw_mode_name;
} cipher_algo_info[] = { CIPHER_ALGO(CBC_NO_PADDING, "CBC"),
			 CIPHER_ALGO(CTR, "CTR"),
			 CIPHER_ALGO(ECB_NO_PADDING, "ECB"),
			 CIPHER_ALGO(XTS, "XTS") };

static smw_cipher_mode_t get_cipher_mode_name(psa_algorithm_t alg)
{
	unsigned int i;
	unsigned int size = ARRAY_SIZE(cipher_algo_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
		if (cipher_algo_info[i].psa_alg_id == alg)
			return cipher_algo_info[i].smw_mode_name;
	}

	return NULL;
}

#define HASH_ALGO(_id, _name, _length, _block_size)                            \
	{                                                                      \
		.psa_alg_id = PSA_ALG_##_id, .smw_alg_name = _name,            \
		.length = _length, .block_size = _block_size                   \
	}

static const struct hash_algo_info {
	psa_algorithm_t psa_alg_id;
	smw_hash_algo_t smw_alg_name;
	size_t length;
	size_t block_size;
} hash_algo_info[] = { HASH_ALGO(MD5, "MD5", 16, 64),
		       HASH_ALGO(SHA_1, "SHA1", 20, 64),
		       HASH_ALGO(SHA_224, "SHA224", 28, 64),
		       HASH_ALGO(SHA_256, "SHA256", 32, 64),
		       HASH_ALGO(SHA_384, "SHA384", 48, 128),
		       HASH_ALGO(SHA_512, "SHA512", 64, 128),
		       HASH_ALGO(SM3, "SM3", 32, 64) };

static const struct hash_algo_info *get_hash_algo_info(psa_algorithm_t alg)
{
	unsigned int i;
	unsigned int size = ARRAY_SIZE(hash_algo_info);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
		if (hash_algo_info[i].psa_alg_id == alg)
			return &hash_algo_info[i];
	}

	return NULL;
}

static smw_hash_algo_t get_hash_algo_name(psa_algorithm_t alg)
{
	const struct hash_algo_info *info = get_hash_algo_info(alg);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return NULL;

	return info->smw_alg_name;
}

__export size_t psa_cipher_encrypt_output_size(psa_key_type_t key_type,
					       psa_algorithm_t alg,
					       size_t input_length)
{
	if (PSA_ALG_IS_CIPHER(alg))
		return input_length + psa_cipher_iv_length(key_type, alg);

	return 0;
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

static psa_status_t
set_signature_attributes_list(psa_algorithm_t alg,
			      unsigned char **attributes_list,
			      unsigned int *attributes_list_length)
{
	unsigned char *p;
	const char *sign_type_str;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*attributes_list = NULL;
	*attributes_list_length = 0;

	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg))
		sign_type_str = RSASSA_PKCS1_V1_5_STR;
	else if (PSA_ALG_IS_RSA_PSS(alg))
		sign_type_str = RSASSA_PSS_STR;
	else
		return PSA_SUCCESS;

	*attributes_list_length +=
		SMW_TLV_ELEMENT_LENGTH(SIGNATURE_TYPE_STR,
				       SMW_UTILS_STRLEN(sign_type_str) + 1);

	*attributes_list = SMW_UTILS_MALLOC(*attributes_list_length);
	if (!*attributes_list)
		return PSA_ERROR_INSUFFICIENT_MEMORY;

	p = *attributes_list;

	smw_tlv_set_string(&p, SIGNATURE_TYPE_STR, sign_type_str);

	SMW_DBG_ASSERT(*attributes_list_length ==
		       (unsigned int)(p - *attributes_list));

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
	(void)key;
	(void)alg;
	(void)nonce;
	(void)nonce_length;
	(void)additional_data;
	(void)additional_data_length;
	(void)ciphertext;
	(void)ciphertext_length;
	(void)plaintext;
	(void)plaintext_size;
	(void)plaintext_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	(void)key;
	(void)alg;
	(void)nonce;
	(void)nonce_length;
	(void)additional_data;
	(void)additional_data_length;
	(void)plaintext;
	(void)plaintext_length;
	(void)ciphertext;
	(void)ciphertext_size;
	(void)ciphertext_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
				    const char *operation_name,
				    struct smw_key_descriptor *key_descriptor,
				    struct smw_cipher_args *args)
{
	psa_status_t psa_status = PSA_SUCCESS;
	enum smw_status_code status;
	struct smw_cipher_init_args *init = &args->init;
	struct smw_cipher_data_args *data = &args->data;
	psa_key_type_t key_type = 0;
	unsigned char *iv = NULL;

	if (!PSA_ALG_IS_CIPHER(alg) || !input || !input_length || !output ||
	    !output_size || !output_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	key_descriptor->id = key;

	status = smw_get_key_type_name(key_descriptor);
	if (status != SMW_STATUS_OK)
		return util_smw_to_psa_status(status);

	key_type = get_psa_key_type(key_descriptor->type_name);
	if (key_type == PSA_KEY_TYPE_NONE)
		return PSA_ERROR_INVALID_ARGUMENT;

	if ((alg == PSA_ALG_CBC_NO_PADDING || alg == PSA_ALG_ECB_NO_PADDING) &&
	    input_length % PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type))
		return PSA_ERROR_INVALID_ARGUMENT;

	init->mode_name = get_cipher_mode_name(alg);
	if (!init->mode_name)
		return PSA_ERROR_NOT_SUPPORTED;

	init->iv_length = PSA_CIPHER_IV_LENGTH(key_type, alg);

	if (!SMW_UTILS_STRCMP(operation_name, "ENCRYPT")) {
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
	} else if (!SMW_UTILS_STRCMP(operation_name, "DECRYPT")) {
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

	init->operation_name = operation_name;

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
	psa_status_t psa_status;
	struct smw_cipher_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	psa_status = set_cipher_args(key, alg, input, input_length, output,
				     output_size, output_length, "DECRYPT",
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
	psa_status_t psa_status;
	struct smw_cipher_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	psa_status = set_cipher_args(key, alg, input, input_length, output,
				     output_size, output_length, "ENCRYPT",
				     &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		goto end;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_cipher,
				  &args, &args.init.subsystem_name);

	if (psa_status == PSA_SUCCESS) {
		*output_length = args.data.output_length + args.init.iv_length;
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
	args.output_length = output_size;

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
	psa_status_t psa_status;
	uint8_t hash_computed[PSA_HASH_MAX_SIZE];
	size_t hash_computed_length = 0;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	psa_status =
		psa_hash_compute(alg, input, input_length, hash_computed,
				 sizeof(hash_computed), &hash_computed_length);

	if (psa_status != PSA_SUCCESS)
		return psa_status;

	if (hash_computed_length != hash_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	for (i = 0; i < hash_length; i++)
		if (hash[i] != hash_computed[i])
			return PSA_ERROR_INVALID_SIGNATURE;

	return PSA_SUCCESS;
}

__export psa_status_t psa_hash_compute(psa_algorithm_t alg,
				       const uint8_t *input,
				       size_t input_length, uint8_t *hash,
				       size_t hash_size, size_t *hash_length)
{
	psa_status_t psa_status;
	struct smw_hash_args args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	args.algo_name = get_hash_algo_name(alg);
	if (!args.algo_name)
		return PSA_ERROR_NOT_SUPPORTED;

	args.input = (unsigned char *)input;
	args.input_length = input_length;
	args.output = hash;
	args.output_length = hash_size;

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
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)mac;
	(void)mac_size;
	(void)mac_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)mac;
	(void)mac_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	enum smw_status_code status;
	const char *algo_name = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key_descriptor->id = key;

	status = smw_get_key_type_name(key_descriptor);
	if (status != SMW_STATUS_OK)
		return util_smw_to_psa_status(status);

	if ((!hashed && !PSA_ALG_IS_SIGN_MESSAGE(alg)) ||
	    (hashed && !PSA_ALG_IS_SIGN_HASH(alg)))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (!hashed) {
		algo_name = get_hash_algo_name(PSA_ALG_GET_HASH(alg));
		if (!algo_name)
			return PSA_ERROR_INVALID_ARGUMENT;
	}

	args->key_descriptor = key_descriptor;
	args->algo_name = algo_name;
	args->message = (unsigned char *)message;
	args->message_length = message_length;
	args->signature = signature;
	args->signature_length = signature_size;

	return set_signature_attributes_list(alg, &args->attributes_list,
					     &args->attributes_list_length);
}

static psa_status_t sign_common(psa_key_id_t key, psa_algorithm_t alg,
				const uint8_t *message, size_t message_length,
				uint8_t *signature, size_t signature_size,
				size_t *signature_length, bool hashed)
{
	psa_status_t psa_status;
	struct smw_sign_verify_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	psa_status = set_sign_verify_args(key, alg, message, message_length,
					  signature, signature_size, hashed,
					  &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_sign,
				  &args, &args.subsystem_name);

	if (psa_status == PSA_SUCCESS && signature_length)
		*signature_length = args.signature_length;

	if (args.attributes_list)
		SMW_UTILS_FREE(args.attributes_list);

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
	psa_status_t psa_status;
	struct smw_sign_verify_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	if (!signature || !signature_length)
		return PSA_ERROR_INVALID_SIGNATURE;

	psa_status =
		set_sign_verify_args(key, alg, message, message_length,
				     (uint8_t *)signature, signature_length,
				     hashed, &key_descriptor, &args);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	psa_status = call_smw_api((enum smw_status_code(*)(void *))smw_verify,
				  &args, &args.subsystem_name);

	if (args.attributes_list)
		SMW_UTILS_FREE(args.attributes_list);

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
