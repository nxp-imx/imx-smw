// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "psa/crypto.h"

#include "smw_crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "util_status.h"

enum smw_status_code call_smw_api(enum smw_status_code (*api)(void *a),
				  void *args,
				  struct smw_config_psa_config *config,
				  smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = api(args);
	if (config->alt && status == SMW_STATUS_OPERATION_NOT_SUPPORTED &&
	    subsystem_name && *subsystem_name) {
		*subsystem_name = NULL;
		status = api(args);
	}

	return status;
}

static smw_subsystem_t get_subsystem_name(struct smw_config_psa_config *config)
{
	if (config->subsystem_id != SUBSYSTEM_ID_INVALID)
		return smw_config_get_subsystem_name(config->subsystem_id);

	return NULL;
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

__export psa_status_t psa_cipher_decrypt(psa_key_id_t key, psa_algorithm_t alg,
					 const uint8_t *input,
					 size_t input_length, uint8_t *output,
					 size_t output_size,
					 size_t *output_length)
{
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)output;
	(void)output_size;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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

__export psa_status_t psa_copy_key(psa_key_id_t source_key,
				   const psa_key_attributes_t *attributes,
				   psa_key_id_t *target_key)
{
	(void)source_key;
	(void)attributes;
	(void)target_key;

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

__export psa_status_t psa_destroy_key(psa_key_id_t key)
{
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_export_key(psa_key_id_t key, uint8_t *data,
				     size_t data_size, size_t *data_length)
{
	(void)key;
	(void)data;
	(void)data_size;
	(void)data_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data,
					    size_t data_size,
					    size_t *data_length)
{
	(void)key;
	(void)data;
	(void)data_size;
	(void)data_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
				       psa_key_id_t *key)
{
	(void)attributes;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_rng_args args = { 0 };
	struct smw_config_psa_config config;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	smw_config_get_psa_config(&config);

	args.subsystem_name = get_subsystem_name(&config);
	args.output = output;
	args.output_length = output_size;

	if (output_size)
		status = call_smw_api((enum smw_status_code(*)(void *))smw_rng,
				      &args, &config, &args.subsystem_name);

	return util_smw_to_psa_status(status);
}

__export psa_status_t psa_get_key_attributes(psa_key_id_t key,
					     psa_key_attributes_t *attributes)
{
	(void)key;
	(void)attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	(void)alg;
	(void)input;
	(void)input_length;
	(void)hash;
	(void)hash_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_hash_compute(psa_algorithm_t alg,
				       const uint8_t *input,
				       size_t input_length, uint8_t *hash,
				       size_t hash_size, size_t *hash_length)
{
	(void)alg;
	(void)input;
	(void)input_length;
	(void)hash;
	(void)hash_size;
	(void)hash_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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

__export psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
				     const uint8_t *data, size_t data_length,
				     psa_key_id_t *key)
{
	(void)attributes;
	(void)data;
	(void)data_length;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
				size_t *capacity)
{
	(void)operation;
	(void)capacity;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
			       psa_key_derivation_step_t step,
			       const uint8_t *data, size_t data_length)
{
	(void)operation;
	(void)step;
	(void)data;
	(void)data_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
			     psa_key_derivation_step_t step, psa_key_id_t key)
{
	(void)operation;
	(void)step;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 psa_key_id_t private_key,
				 const uint8_t *peer_key,
				 size_t peer_key_length)
{
	(void)operation;
	(void)step;
	(void)private_key;
	(void)peer_key;
	(void)peer_key_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
				uint8_t *output, size_t output_length)
{
	(void)operation;
	(void)output;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
			      psa_key_derivation_operation_t *operation,
			      psa_key_id_t *key)
{
	(void)attributes;
	(void)operation;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
				size_t capacity)
{
	(void)operation;
	(void)capacity;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
			 psa_algorithm_t alg)
{
	(void)operation;
	(void)alg;

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

__export void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
	(void)attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

__export psa_status_t psa_sign_hash(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *hash, size_t hash_length,
				    uint8_t *signature, size_t signature_size,
				    size_t *signature_length)
{
	(void)key;
	(void)alg;
	(void)hash;
	(void)hash_length;
	(void)signature;
	(void)signature_size;
	(void)signature_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_sign_message(psa_key_id_t key, psa_algorithm_t alg,
				       const uint8_t *input,
				       size_t input_length, uint8_t *signature,
				       size_t signature_size,
				       size_t *signature_length)
{
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)signature;
	(void)signature_size;
	(void)signature_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_verify_hash(psa_key_id_t key, psa_algorithm_t alg,
				      const uint8_t *hash, size_t hash_length,
				      const uint8_t *signature,
				      size_t signature_length)
{
	(void)key;
	(void)alg;
	(void)hash;
	(void)hash_length;
	(void)signature;
	(void)signature_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_verify_message(psa_key_id_t key, psa_algorithm_t alg,
					 const uint8_t *input,
					 size_t input_length,
					 const uint8_t *signature,
					 size_t signature_length)
{
	(void)key;
	(void)alg;
	(void)input;
	(void)input_length;
	(void)signature;
	(void)signature_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}
