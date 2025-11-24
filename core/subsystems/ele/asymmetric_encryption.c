// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "asymmetric_encryption.h"

#include "common.h"

#define ASYMM_ENC_ALGO(_smw_mode_id, _hsm_algo)                                \
	{                                                                      \
		.asymm_enc_mode_id =                                           \
			SMW_CONFIG_ASYMM_ENC_MODE_ID_##_smw_mode_id,           \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_INVALID,                    \
		.hsm_algo = ALGO_RSA_PKCS1_##_hsm_algo,                        \
	}

#define ASYMM_ENC_OAEP_ALGO(_hash_id)                                          \
	{                                                                      \
		.asymm_enc_mode_id = SMW_CONFIG_ASYMM_ENC_MODE_ID_OAEP,        \
		.hash_id = SMW_CONFIG_HASH_ALGO_ID_##_hash_id,                 \
		.hsm_algo = ALGO_RSA_PKCS1_OAEP_##_hash_id,                    \
	}

static const struct {
	enum smw_config_asymm_enc_mode_id asymm_enc_mode_id;
	enum smw_config_hash_algo_id hash_id;
	hsm_asymmetric_crypto_algo_t hsm_algo;
} enc_algos[] = {
	ASYMM_ENC_ALGO(PKCS1_1_5, V15_CRYPT), ASYMM_ENC_OAEP_ALGO(SHA1),
	ASYMM_ENC_OAEP_ALGO(SHA224),	      ASYMM_ENC_OAEP_ALGO(SHA256),
	ASYMM_ENC_OAEP_ALGO(SHA384),	      ASYMM_ENC_OAEP_ALGO(SHA512)
};

static int ele_set_encrypt_algo(enum smw_config_asymm_enc_mode_id enc_mode_id,
				enum smw_config_hash_algo_id hash_id,
				hsm_asymmetric_crypto_algo_t *hsm_algo)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int i = 0;

	if (hash_id == SMW_CONFIG_HASH_ALGO_ID_INVALID &&
	    enc_mode_id == SMW_CONFIG_ASYMM_ENC_MODE_ID_OAEP)
		goto end;

	status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	for (; i < ARRAY_SIZE(enc_algos); i++) {
		if (hash_id == enc_algos[i].hash_id &&
		    enc_mode_id == enc_algos[i].asymm_enc_mode_id) {
			*hsm_algo = enc_algos[i].hsm_algo;
			SMW_DBG_PRINTF(VERBOSE, "%s hsm_algo =  0x%08X\n",
				       __func__, *hsm_algo);
			status = SMW_STATUS_OK;
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int open_asymmetric_enc_service(struct hdl *hdl,
				       hsm_hdl_t *asymmetric_enc_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	op_asymmetric_enc_open_args_t asym_open_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	asym_open_args.key_store_handle = hdl->key_store;

	err = hsm_asymmetric_enc_open(hdl->session, &asym_open_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_asymmetric_enc_open returned %d\n", err);
	SMW_DBG_PRINTF(DEBUG, "Open asymmetric_enc_handle: %u\n",
		       asym_open_args.asymmetric_enc_handle);

	*asymmetric_enc_hdl = asym_open_args.asymmetric_enc_handle;

	return ele_convert_err(err);
}

static int close_asymmetric_enc_service(hsm_hdl_t asymmetric_enc_handle)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Close asymmetric_enc_handle: %u\n",
		       asymmetric_enc_handle);

	if (asymmetric_enc_handle)
		err = hsm_asymmetric_enc_close(asymmetric_enc_handle);

	SMW_DBG_PRINTF(DEBUG, "hsm_asymmetric_enc_close returned %d\n", err);

	return ele_convert_err(err);
}

static void set_io_params(enum operation_id operation_id,
			  struct smw_crypto_asymm_enc_args *args,
			  op_asymmetric_enc_args_t *op_args)
{
	if (operation_id == OPERATION_ID_ASYMM_ENCRYPT) {
		op_args->plaintext_addr = smw_crypto_get_asymm_enc_input(args);
		op_args->plaintext_size =
			smw_crypto_get_asymm_enc_input_len(args);
		op_args->ciphertext_addr =
			smw_crypto_get_asymm_enc_output(args);
		op_args->ciphertext_size =
			smw_crypto_get_asymm_enc_output_len(args);

		op_args->flags |= HSM_ASYM_FLAGS_ENCRYPT;
	} else {
		op_args->ciphertext_addr = smw_crypto_get_asymm_enc_input(args);
		op_args->ciphertext_size =
			smw_crypto_get_asymm_enc_input_len(args);
		op_args->plaintext_addr = smw_crypto_get_asymm_enc_output(args);
		op_args->plaintext_size =
			smw_crypto_get_asymm_enc_output_len(args);

		op_args->flags |= HSM_ASYM_FLAGS_DECRYPT;
	}

	if (args->attrs.mode_id == SMW_CONFIG_ASYMM_ENC_MODE_ID_OAEP) {
		op_args->label_size = smw_crypto_get_asymm_enc_salt_len(args);
		op_args->label_addr = smw_crypto_get_asymm_enc_salt(args);
	}
}

static void set_output_length(enum operation_id operation_id,
			      struct smw_crypto_asymm_enc_args *args,
			      op_asymmetric_enc_args_t *op_args)
{
	unsigned int output_len = 0;

	if (operation_id == OPERATION_ID_ASYMM_ENCRYPT)
		output_len = op_args->exp_ciphertext_size;
	else
		output_len = op_args->exp_plaintext_size;

	smw_crypto_set_asymm_enc_output_len(args, output_len);

	SMW_DBG_PRINTF(VERBOSE, "%s Expected output length = %d\n", __func__,
		       output_len);
}

static int set_rsa_modulus_buffer(op_asymmetric_enc_args_t *op_args,
				  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_OK;

	unsigned char *hex_key_buf = NULL;
	unsigned int hex_key_size = 0;
	unsigned int modulus_len = smw_keymgr_get_modulus_length(key_desc);
	unsigned char *modulus_buffer = smw_keymgr_get_modulus(key_desc);

	status = is_rsa_pub_expo_default(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
					      modulus_buffer, modulus_len,
					      &hex_key_buf, &hex_key_size);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args->input_plainkey_size = hex_key_size;
	op_args->key_addr = hex_key_buf;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_rsa_private_key_buffer(op_asymmetric_enc_args_t *op_args,
				      struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int private_buf_len = smw_keymgr_get_private_length(key_desc);
	unsigned char *private_buffer = smw_keymgr_get_private_data(key_desc);
	unsigned int modulus_len = smw_keymgr_get_modulus_length(key_desc);
	unsigned char *modulus_buffer = smw_keymgr_get_modulus(key_desc);
	unsigned char *hex_private_buffer = NULL;
	unsigned char *hex_modulus = NULL;
	unsigned char *rsa_private_key_buffer = NULL;
	unsigned int hex_private_len = 0;
	unsigned int hex_modulus_len = 0;

	if (!private_buf_len || !private_buffer || !modulus_len ||
	    !modulus_buffer)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
					      private_buffer, private_buf_len,
					      &hex_private_buffer,
					      &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
					      modulus_buffer, modulus_len,
					      &hex_modulus, &hex_modulus_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (ADD_OVERFLOW(hex_private_len, hex_modulus_len,
			 &op_args->input_plainkey_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	rsa_private_key_buffer = SMW_UTILS_MALLOC(op_args->input_plainkey_size);
	if (!rsa_private_key_buffer) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	SMW_UTILS_MEMCPY(rsa_private_key_buffer, hex_private_buffer,
			 hex_private_len);

	SMW_UTILS_MEMCPY(rsa_private_key_buffer + hex_private_len, hex_modulus,
			 hex_modulus_len);

	op_args->key_addr = rsa_private_key_buffer;

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
		if (hex_private_buffer)
			SMW_UTILS_FREE(hex_private_buffer);

		if (hex_modulus)
			SMW_UTILS_FREE(hex_modulus);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int set_key(enum operation_id operation_id,
		   struct smw_crypto_asymm_enc_args *args,
		   op_asymmetric_enc_args_t *op_args)
{
	int status = SMW_STATUS_OK;

	hsm_key_type_t ele_key_type = (hsm_key_type_t)0;
	hsm_pubkey_type_t ele_pubkey_type = (hsm_pubkey_type_t)0;
	struct smw_keymgr_descriptor *key_desc = &args->key_desc;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	if (key_identifier->type_id != SMW_CONFIG_KEY_TYPE_ID_RSA) {
		SMW_DBG_PRINTF(ERROR, "Only RSA key type is supported.\n");
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	if (key_identifier->s_id) {
		op_args->key_id = key_identifier->s_id;
		op_args->flags |= HSM_ASYM_FLAGS_OPAQUE_KEY;
		goto exit;
	}

	op_args->flags |= HSM_ASYM_FLAGS_PLAINTEXT_KEY;

	if (SET_OVERFLOW(key_identifier->security_size,
			 op_args->input_plainkey_security_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	if (operation_id == OPERATION_ID_ASYMM_ENCRYPT) {
		status = set_rsa_modulus_buffer(op_args, key_desc);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = ele_set_pubkey_type(key_identifier->type_id,
					     &ele_pubkey_type);
		if (status != SMW_STATUS_OK)
			goto exit;

		op_args->input_plainkey_type = ele_pubkey_type;
	} else {
		status = set_rsa_private_key_buffer(op_args, key_desc);
		if (status != SMW_STATUS_OK)
			goto exit;

		status = ele_get_key_type(key_identifier->type_id,
					  &ele_key_type);
		if (status != SMW_STATUS_OK)
			goto exit;

		op_args->input_plainkey_type = ele_key_type;
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int asymm_encrypt_decrypt(struct subsystem_context *ele_ctx,
				 enum operation_id operation_id,
				 void *asymm_enc_args)

{
	int status = SMW_STATUS_INVALID_PARAM;
	int temp_status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	hsm_hdl_t asymmetric_enc_hdl = 0;
	op_asymmetric_enc_args_t op_args = { 0 };

	struct smw_crypto_asymm_enc_args *args = asymm_enc_args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	status = ele_set_encrypt_algo(args->attrs.mode_id, args->attrs.hash_id,
				      &op_args.algorithm);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_key(operation_id, args, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	set_io_params(operation_id, args, &op_args);

	status = ele_open_key_store_service(&ele_ctx->hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	status =
		open_asymmetric_enc_service(&ele_ctx->hdl, &asymmetric_enc_hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.asymmetric_enc_handle = asymmetric_enc_hdl;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_asymmetric_enc()\n"
		       "op_asymmetric_enc_args_t\n"
		       "    asymmetric_enc_handle: %u\n"
		       "    key_id: 0x%08X\n"
		       "    key buffer\n"
		       "      - buffer: %p\n"
		       "      - key size: %d\n"
		       "      - security size: %d\n"
		       "      - type: 0x%08X\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    Plaintext\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n"
		       "    Ciphertext\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n"
		       "    Label\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.asymmetric_enc_handle,
		       op_args.key_id, op_args.key_addr,
		       op_args.input_plainkey_size,
		       op_args.input_plainkey_security_size,
		       op_args.input_plainkey_type, op_args.algorithm,
		       op_args.flags, op_args.plaintext_addr,
		       op_args.plaintext_size, op_args.ciphertext_addr,
		       op_args.ciphertext_size, op_args.label_addr,
		       op_args.label_size);

	err = hsm_asymmetric_enc(ele_ctx->hdl.session, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_asymmetric_enc returned %d\n", err);

	status = ele_convert_err(err);

	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto end;

	SMW_DBG_PRINTF(DEBUG, "Expected exp_ciphertext_size = %u\n",
		       op_args.exp_ciphertext_size);
	SMW_DBG_PRINTF(DEBUG, "Expected exp_plaintext_size = %u\n",
		       op_args.exp_plaintext_size);

	set_output_length(operation_id, args, &op_args);

end:
	/*
	 * Release dynamically allocated key buffers:
	 * - For encryption: key_addr points to modulus buffer, free only if
	 *   key buffer was encoded in Base64 format.
	 * - For decryption: key_addr holds allocated concatenation of private
	 *   exponent and modulus, must be freed.
	 */
	if (op_args.key_addr) {
		if (operation_id == OPERATION_ID_ASYMM_ENCRYPT) {
			if (args && args->key_desc.format_id ==
					    SMW_KEYMGR_FORMAT_ID_BASE64)
				SMW_UTILS_FREE(op_args.key_addr);
		} else {
			SMW_UTILS_FREE(op_args.key_addr);
		}
	}

	temp_status = close_asymmetric_enc_service(asymmetric_enc_hdl);

	if (status == SMW_STATUS_OK)
		status = temp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

bool ele_asymmetric_encryption_handle(struct subsystem_context *ele_ctx,
				      enum operation_id operation_id,
				      void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_ASYMM_ENCRYPT:
	case OPERATION_ID_ASYMM_DECRYPT:
		*status = asymm_encrypt_decrypt(ele_ctx, operation_id, args);
		break;

	default:
		return false;
	}

	return true;
}
