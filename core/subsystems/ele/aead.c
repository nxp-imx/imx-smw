// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "aead.h"
#include "common.h"

#define MAX_IV_LEN  12
#define ELE_TAG_LEN 16

#define AEAD_ALGO(_key_type_id, _aead_mode_id)                                 \
	{                                                                      \
		.key_type_id = SMW_CONFIG_KEY_TYPE_ID_##_key_type_id,          \
		.aead_mode_id = SMW_CONFIG_AEAD_MODE_ID_##_aead_mode_id,       \
		.aead_algo = HSM_AEAD_ALGO_##_aead_mode_id                     \
	}

/**
 * struct aead_context - AEAD context
 * @iv: Out IV buffer
 * @iv_len: Length of @iv
 * @ele_ctx: ELE operation context
 * @ele_ctx_size: ELE operation context size
 * @ele_cipher_handle: ELE cipher handle
 * @opaque_key: True, if key is opaque
 * @op_type_id: Operation type ID (encryption or decryption)
 * @ele_aead_algo: ELE AEAD algorithm identifier
 * @remaining_buffered_len: Remaining buffered bytes (Updated during UPDATE)
 */
struct aead_context {
	unsigned char iv[MAX_IV_LEN];
	unsigned int iv_len;
	uint8_t *ele_ctx;
	uint16_t ele_ctx_size;
	hsm_hdl_t ele_cipher_handle;
	bool opaque_key;
	enum smw_config_aead_op_type_id op_type_id;
	hsm_op_auth_enc_algo_t ele_aead_algo;
	unsigned int remaining_buffered_len;
};

static const struct {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_aead_mode_id aead_mode_id;
	hsm_op_auth_enc_algo_t aead_algo;
} aead_algos[] = { AEAD_ALGO(AES, CCM), AEAD_ALGO(AES, GCM),
		   AEAD_ALGO(AES, CHACHA20_POLY1305) };

static int set_aead_algo(enum smw_config_key_type_id key_type_id,
			 enum smw_config_aead_mode_id aead_mode_id,
			 hsm_op_auth_enc_algo_t *aead_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(aead_algos); i++) {
		if (key_type_id == aead_algos[i].key_type_id &&
		    aead_mode_id == aead_algos[i].aead_mode_id) {
			*aead_algo = aead_algos[i].aead_algo;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_operation_type_flag() - Set encryption/decryption flag
 * @aead_args: Pointer to AEAD arguments
 * @aead_ctx: Pointer to AEAD context (for multi-part operations)
 * @flags: Pointer to flags to be updated
 *
 * Sets HSM_AUTH_ENC_FLAGS_ENCRYPT or HSM_AUTH_ENC_FLAGS_DECRYPT flag
 * based on the operation step:
 * - ONESHOT/INIT/FINAL: Uses aead_args->op_type_id
 * - UPDATE/UPDATE AAD: Uses aead_ctx->op_type_id (set during INIT)
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid parameters
 */
static int set_operation_type_flag(struct smw_crypto_aead_args *aead_args,
				   struct aead_context *aead_ctx,
				   hsm_op_auth_enc_new_flags_t *flags)
{
	int status = SMW_STATUS_INVALID_PARAM;
	bool is_encrypt = false;

	if (!aead_args || !flags)
		return status;

	switch (aead_args->op_step) {
	case SMW_OP_STEP_ONESHOT:
	case SMW_OP_STEP_INIT:
	case SMW_OP_STEP_FINAL:
		if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
			is_encrypt = true;

		break;

	case SMW_OP_STEP_UPDATE:
		if (!aead_ctx)
			return status;

		if (aead_ctx->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
			is_encrypt = true;

		break;

	default:
		return status;
	}

	if (is_encrypt)
		*flags |= HSM_AUTH_ENC_FLAGS_ENCRYPT;
	else
		*flags |= HSM_AUTH_ENC_FLAGS_DECRYPT;

	return SMW_STATUS_OK;
}

static int set_aead_flags(struct smw_crypto_aead_args *aead_args,
			  struct aead_context *aead_ctx,
			  hsm_op_auth_enc_new_flags_t *ele_flags)
{
	int status = SMW_STATUS_OK;

	unsigned int user_iv_len = smw_crypto_get_aead_user_iv_len(aead_args);

	switch (aead_args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		*ele_flags = HSM_AUTH_ENC_FLAGS_ONE_SHOT;
		break;

	case SMW_OP_STEP_INIT:
		*ele_flags = HSM_AUTH_ENC_FLAGS_INIT;
		break;

	case SMW_OP_STEP_UPDATE:
		*ele_flags = HSM_AUTH_ENC_FLAGS_UPDATE_DATA;
		break;

	case SMW_OP_STEP_FINAL:
		if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
			*ele_flags = HSM_AUTH_ENC_FLAGS_FINALIZE;
		else
			*ele_flags = HSM_AUTH_ENC_FLAGS_FINALIZE_VERIFY;

		break;

	default:
		break;
	}

	status = set_operation_type_flag(aead_args, aead_ctx, ele_flags);
	if (status != SMW_STATUS_OK)
		return status;

	if (aead_args->op_step != SMW_OP_STEP_ONESHOT &&
	    aead_args->op_step != SMW_OP_STEP_INIT)
		goto end;

	/* Handle GCM encryption IV generation flags for ONESHOT and INIT */
	if (aead_args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT &&
	    aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_GCM) {
		if (user_iv_len < MAX_IV_LEN) {
			if (smw_crypto_get_aead_iv_len(aead_args) <
			    MAX_IV_LEN) {
				status = SMW_STATUS_INVALID_IV_SIZE;
			} else if (!user_iv_len) {
				*ele_flags |=
					HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
			} else {
				*ele_flags |=
					HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
			}
		} else if (user_iv_len != MAX_IV_LEN) {
			status = SMW_STATUS_INVALID_IV_SIZE;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void set_all_outputs_length(struct smw_crypto_aead_args *args,
				   unsigned int output_len)
{
	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		smw_crypto_set_aead_output_iv_len(args, MAX_IV_LEN);
		smw_crypto_set_aead_tag_len(args, ELE_TAG_LEN);
	}

	smw_crypto_set_aead_output_len(args, output_len);
}

/**
 * set_output_iv() - Copy the IV buffer to output_iv
 * @args: Pointer to internal AEAD arguments
 * @op_args: Pointer to ELE AEAD operation arguments
 *
 * IV provided by user (iv_len = 12):
 * Copy the IV buffer from user IV buffer to output_iv field.
 *
 * IV generated (partially or entirely) by FW (iv_len = 0 or 4):
 * Copy the IV buffer from @op_args->iv_out buffer to output_iv field.
 *
 * Return:
 * SMW_STATUS_OK                 - Success
 * SMW_STATUS_SUBSYSTEM_FAILURE  - Subsystem don't return IV buffer
 */
static int set_output_iv(struct smw_crypto_aead_args *args,
			 op_auth_enc_new_args_t *op_args)
{
	int status = SMW_STATUS_OK;

	unsigned int iv_len = smw_crypto_get_aead_user_iv_len(args);
	unsigned char *output_iv = smw_crypto_get_aead_output_iv(args);
	unsigned char *iv = smw_crypto_get_aead_user_iv(args);

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_DECRYPT)
		return status;

	if (output_iv) {
		if (iv_len < MAX_IV_LEN) {
			if (op_args->iv_out)
				SMW_UTILS_MEMCPY(output_iv, op_args->iv_out,
						 MAX_IV_LEN);
			else
				status = SMW_STATUS_SUBSYSTEM_FAILURE;
		} else if (iv) {
			SMW_UTILS_MEMCPY(output_iv, iv, MAX_IV_LEN);
		}
	}

	return status;
}

static int get_private_key_buffer(op_auth_enc_new_args_t *op_args,
				  struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int private_buf_len = smw_keymgr_get_private_length(key_desc);
	unsigned char *private_buffer = smw_keymgr_get_private_data(key_desc);
	unsigned int hex_private_len = 0;

	if (!private_buf_len || !private_buffer)
		goto end;

	status = smw_utils_key_set_hex_buffer(key_desc->format_id,
					      private_buffer, private_buf_len,
					      &op_args->key, &hex_private_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (SET_OVERFLOW(hex_private_len, op_args->key_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

end:
	return status;
}

static int set_key(struct smw_crypto_aead_args *aead_args,
		   op_auth_enc_new_args_t *op_args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor *key_desc = &aead_args->key_desc;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	hsm_key_type_t ele_key_type = (hsm_key_type_t)0;

	if (key_identifier->s_id) {
		op_args->key_id = key_identifier->s_id;
	} else {
		/* AEAD using plaintext key buffer */
		op_args->flags |= HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;

		status = ele_get_key_type(key_identifier->type_id,
					  &ele_key_type);
		if (status != SMW_STATUS_OK)
			goto end;

		op_args->key_type = ele_key_type;

		status = get_private_key_buffer(op_args, key_desc);
	}

end:
	return status;
}

/**
 * get_input_data_len() - Return the length of the input data buffer
 * @args: Pointer to internal AEAD argument structure
 * @input_data_length: Pointer to hold the input data buffer length
 *
 * For encryption operation, it returns the length of the input data.
 * For decryption operation, it returns length of the ciphertext (excluding tag
 * length, if tag is part of the output buffer) for ONESHOT or FINAL steps.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int get_input_data_len(struct smw_crypto_aead_args *args,
			      unsigned int *input_data_length)
{
	int status = SMW_STATUS_OK;

	*input_data_length = smw_crypto_get_aead_input_len(args);

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_DECRYPT &&
	    (args->op_step == SMW_OP_STEP_ONESHOT ||
	     args->op_step == SMW_OP_STEP_FINAL)) {
		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (DEC_OVERFLOW(*input_data_length,
					 smw_crypto_get_aead_tag_len(args)))
				status = SMW_STATUS_INVALID_PARAM;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned with input length = %u\n",
		       __func__, *input_data_length);
	return status;
}

/**
 * get_output_data_len() - Return the length of the output data buffer
 * @args: Pointer to internal AEAD arguments
 * @output_data_length: Pointer to hold the output data buffer length
 *
 * For encryption operation,
 *  - ONESHOT or FINAL steps: it returns length of the ciphertext (excluding tag
 *     length, if tag is part of the output buffer)
 *  - UPDATE step: it returns length of the ciphertext buffer.
 * For decryption operation, it returns the length of the plaintext buffer.
 *
 * Return:
 * SMW_STATUS_OK
 * SMW_STATUS_INVALID_PARAM
 */
static int get_output_data_len(struct smw_crypto_aead_args *args,
			       unsigned int *output_data_length)
{
	int status = SMW_STATUS_OK;
	unsigned int input_data_length = 0;

	*output_data_length = smw_crypto_get_aead_output_len(args);
	input_data_length = smw_crypto_get_aead_input_len(args);

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT &&
	    (args->op_step == SMW_OP_STEP_ONESHOT ||
	     args->op_step == SMW_OP_STEP_FINAL)) {
		if (!smw_crypto_is_aead_tag_field_set(args)) {
			if (DEC_OVERFLOW(*output_data_length,
					 smw_crypto_get_aead_tag_len(args)))
				status = SMW_STATUS_OUTPUT_TOO_SHORT;

			if (args->op_step == SMW_OP_STEP_ONESHOT &&
			    *output_data_length > input_data_length)
				*output_data_length = input_data_length;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned with output length = %u\n",
		       __func__, *output_data_length);

	return status;
}

/**
 * set_output_length() - Set the output buffer length
 * @aead_args: Pointer to internal AEAD arguments
 * @aead_ctx: Pointer to AEAD context
 *
 * Sets the output buffer length based on input buffer length and tag length.
 * Additionally, sets the IV and tag lengths for AEAD encryption operation.
 *
 * ONESHOT operation:
 * - expected_output_length = input_length + tag_length (if tag is part of
 *                                                    output buffer)
 *
 * UPDATE Operation:
 * - The subsystem may buffer incomplete blocks internally,
 *   so output length may be less than input length.
 * - expected_output_length = input_length (as maximum estimate)
 *
 * FINAL Operation:
 * - The output length includes:
 *   1. Remaining buffered bytes from previous UPDATE operations
 *   2. Input provided to FINAL (if any) - will be processed via implicit UPDATE
 *   3. Tag length (if tag is part of output buffer)
 *
 *   expected_output_length = remaining_buffered_len +
 *                            input_length (from FINAL) +
 *                            tag_length (if applicable)
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int set_output_length(struct smw_crypto_aead_args *aead_args,
			     struct aead_context *aead_ctx)
{
	int status = SMW_STATUS_OK;
	unsigned int expected_output_len = 0;
	unsigned int input_len = 0;
	struct crypto_output_params params = { 0 };

	status = get_input_data_len(aead_args, &input_len);
	if (status != SMW_STATUS_OK)
		goto end;

	params.input_len = input_len;
	params.op_step = aead_args->op_step;

	if (aead_args->op_step == SMW_OP_STEP_ONESHOT ||
	    aead_args->op_step == SMW_OP_STEP_FINAL) {
		if (aead_args->op_step == SMW_OP_STEP_FINAL) {
			if (!aead_ctx) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}

			params.remaining_buffered_len =
				aead_ctx->remaining_buffered_len;
		}

		/*
		 * Set tag_len based on whether tag should be added to output.
		 *
		 * tag_len is non-zero ONLY when tag should be in output buffer:
		 * - AEAD encryption with tag in output buffer: tag_len = ELE_TAG_LEN
		 * - AEAD encryption with dedicated tag field: tag_len = 0 (not added)
		 * - AEAD decryption: tag_len = 0 (no tag in output)
		 */
		if (aead_args->op_type_id ==
		    SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
			if (!smw_crypto_is_aead_tag_field_set(aead_args))
				params.tag_len = ELE_TAG_LEN;
		}
	}

	status = ele_calculate_expected_output_len(&params,
						   &expected_output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	set_all_outputs_length(aead_args, expected_output_len);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned with output length = %u\n",
		       __func__, expected_output_len);
	return status;
}

/**
 * validate_iv_length() - Validate IV length for specific AEAD modes
 * @aead_args: Pointer to internal AEAD arguments
 *
 * CCM and ChaCha20-Poly1305 require IV length to be exactly 12 bytes.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_INVALID_IV_SIZE   - Invalid IV size
 */
static int validate_iv_length(struct smw_crypto_aead_args *aead_args)
{
	if ((aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM ||
	     aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CHACHA20_POLY1305) &&
	    smw_crypto_get_aead_user_iv_len(aead_args) != MAX_IV_LEN) {
		return SMW_STATUS_INVALID_IV_SIZE;
	}

	return SMW_STATUS_OK;
}

/**
 * validate_tag_length() - Validate tag length
 * @aead_args: Pointer to internal AEAD arguments
 *
 * For ELE subsystem, tag length must be 16 bytes.
 * If tag length is less than required, return an error.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Tag length too short
 */
static int validate_tag_length(struct smw_crypto_aead_args *aead_args)
{
	int status = SMW_STATUS_OK;

	if (smw_crypto_get_aead_tag_len(aead_args) < ELE_TAG_LEN)
		status = SMW_STATUS_OUTPUT_TOO_SHORT;

	return status;
}

/**
 * do_aead() - Execute HSM authenticated encryption operation
 * @hdl: Pointer to ELE subsystem handle
 * @cipher_hdl: Pointer to cipher handle
 * @op_args: Pointer to ELE AEAD operation arguments
 * @open_cipher_service_flow: If true, open key store and cipher services
 *
 * Execute the HSM AEAD operation and optionally opens key store and
 * cipher services if requested.
 *
 * Return:
 * SMW_STATUS_OK or error code
 */
static int do_aead(struct hdl *hdl, hsm_hdl_t *cipher_hdl,
		   op_auth_enc_new_args_t *op_args,
		   bool open_cipher_service_flow)
{
	hsm_err_t err = HSM_NO_ERROR;
	int status = SMW_STATUS_OK;

	if (open_cipher_service_flow) {
		status = ele_open_key_store_service(hdl);
		if (status != SMW_STATUS_OK)
			goto end;

		status = open_cipher_service(hdl, cipher_hdl);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_auth_enc_new()\n"
		       "op_auth_enc_new_args_t\n"
		       "    key_identifier: 0x%08X\n"
		       "    key buffer\n"
		       "      - buffer: %p\n"
		       "      - key size: %d\n"
		       "      - type: 0x%08X\n"
		       "    algo: 0x%08X\n"
		       "    flags: 0x%X\n"
		       "    IV_in\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    IV_out\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Tag\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    AAD\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n"
		       "    Input\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n"
		       "    Output\n"
		       "       - buffer: %p\n"
		       "       - size: %d\n"
		       "    Context\n"
		       "       - ctx: %p\n"
		       "       - size: %d\n",
		       __func__, __LINE__, op_args->key_id, op_args->key,
		       op_args->key_size, op_args->key_type, op_args->ae_algo,
		       op_args->flags, op_args->iv_in, op_args->iv_size,
		       op_args->iv_out, op_args->iv_size, op_args->tag,
		       op_args->tag_size, op_args->aad, op_args->aad_size,
		       op_args->input, op_args->input_size, op_args->output,
		       op_args->output_size, op_args->context,
		       op_args->context_size);

	err = hsm_auth_enc_new(*cipher_hdl, op_args);

	SMW_DBG_PRINTF(DEBUG,
		       "hsm_auth_enc_new returned %d, verify_status = 0x%x\n",
		       err, op_args->verify_status);

	SMW_DBG_PRINTF(DEBUG, "Expected output size = %u\n",
		       op_args->exp_output_size);

	status = ele_convert_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}

/**
 * process_aead_output() - Process AEAD operation output
 * @args: Pointer to internal AEAD arguments
 * @op_args: Pointer to ELE AEAD operation arguments
 * @aead_ctx: Pointer to AEAD context (NULL for one-shot operations)
 * @update_output_offset: Bytes already written by update operation (0 if none)
 *
 * This function processes the output of AEAD encryption/decryption operations.
 * It handles:
 * - Check tag validation status for decryption operations
 * - Output length calculation
 * - IV output for encryption (from op_args for oneshot, from context for final)
 * - Setting all output lengths
 *
 * Return:
 * SMW_STATUS_OK                    - Success
 * SMW_STATUS_SIGNATURE_INVALID     - Tag verification failed
 * SMW_STATUS_OPERATION_FAILURE     - Output size overflow
 * SMW_STATUS_SUBSYSTEM_FAILURE     - IV output not available
 */
static int process_aead_output(struct smw_crypto_aead_args *args,
			       op_auth_enc_new_args_t *op_args,
			       struct aead_context *aead_ctx,
			       unsigned int update_output_offset)
{
	int status = SMW_STATUS_OK;
	unsigned int output_length = 0;
	bool is_encrypt_op = false;
	unsigned char *output_iv = NULL;
	unsigned int *buffered_len = NULL;
	unsigned int input_length = smw_crypto_get_aead_input_len(args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
		is_encrypt_op = true;

	/*
	 * If the tag is invalid, verification status is set to
	 * HSM_AEAD_VERIFICATION_STATUS_FAILURE but the API response indicator
	 * returns HSM_NO_ERROR.
	 */
	if (!is_encrypt_op &&
	    (args->op_step == SMW_OP_STEP_FINAL ||
	     args->op_step == SMW_OP_STEP_ONESHOT) &&
	    op_args->verify_status == HSM_AEAD_VERIFICATION_STATUS_FAILURE) {
		status = SMW_STATUS_SIGNATURE_INVALID;
		goto end;
	}

	if (SET_OVERFLOW(op_args->exp_output_size, output_length)) {
		status = SMW_STATUS_OPERATION_FAILURE;
		goto end;
	}

	/* Handle UPDATE operation */
	if (args->op_step == SMW_OP_STEP_UPDATE) {
		smw_crypto_set_aead_output_len(args, output_length);
		buffered_len = &aead_ctx->remaining_buffered_len;

		status = ele_update_buffered_len(buffered_len, input_length,
						 output_length);
		if (status != SMW_STATUS_OK)
			goto end;

		goto end;
	}

	/*
	 * For multi-part final after update:
	 * - op_args->exp_output_size = bytes written by FINAL operation only
	 * - update_output_offset = bytes written by UPDATE operation
	 * - Total output = update_output_offset + exp_output_size
	 */
	if (args->op_step == SMW_OP_STEP_FINAL) {
		if (update_output_offset > 0) {
			if (INC_OVERFLOW(output_length, update_output_offset)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}

		aead_ctx->remaining_buffered_len = 0;
	}

	if (is_encrypt_op) {
		if (args->op_step == SMW_OP_STEP_FINAL ||
		    args->op_step == SMW_OP_STEP_ONESHOT) {
			if (!smw_crypto_is_aead_tag_field_set(args)) {
				if (INC_OVERFLOW(output_length, ELE_TAG_LEN)) {
					status = SMW_STATUS_OPERATION_FAILURE;
					goto end;
				}
			}
		}

		if (args->op_step == SMW_OP_STEP_FINAL) {
			output_iv = smw_crypto_get_aead_output_iv(args);

			if (output_iv && aead_ctx->iv_len)
				SMW_UTILS_MEMCPY(output_iv, aead_ctx->iv,
						 aead_ctx->iv_len);
		} else if (args->op_step == SMW_OP_STEP_ONESHOT) {
			status = set_output_iv(args, op_args);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		set_all_outputs_length(args, output_length);
	} else {
		smw_crypto_set_aead_output_len(args, output_length);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_aead_context() - Initialize the operation context
 * @op_context: Pointer to operation context arguments structure
 * @op_args: Pointer to ELE AEAD operation arguments
 * @cipher_hdl: Cipher handle
 *
 * This function initializes the members of operation context structure.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - One of the parameters is invalid
 */
static int set_aead_context(struct smw_op_context *op_context,
			    struct smw_crypto_aead_args *args,
			    op_auth_enc_new_args_t *op_args,
			    hsm_hdl_t cipher_hdl)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct aead_context *aead_ctx = NULL;
	struct smw_keymgr_descriptor *key_desc = &args->key_desc;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	if (!op_context)
		goto end;

	op_context->op_id = SMW_CRYPTO_OP_ID_AEAD_MULTI_PART;

	aead_ctx = SMW_UTILS_CALLOC(1, sizeof(*aead_ctx));
	if (!aead_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		SMW_DBG_PRINTF(ERROR,
			       "AEAD subsystem context allocation failure\n");
		goto end;
	}

	if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
		if (smw_crypto_get_aead_user_iv_len(args) < MAX_IV_LEN) {
			if (op_args->iv_out) {
				SMW_UTILS_MEMCPY(aead_ctx->iv, op_args->iv_out,
						 MAX_IV_LEN);
				aead_ctx->iv_len = MAX_IV_LEN;
			} else {
				status = SMW_STATUS_SUBSYSTEM_FAILURE;
				goto end;
			}

		} else if (smw_crypto_get_aead_user_iv(args)) {
			SMW_UTILS_MEMCPY(aead_ctx->iv,
					 smw_crypto_get_aead_user_iv(args),
					 MAX_IV_LEN);
			aead_ctx->iv_len = MAX_IV_LEN;
		}
	}

	aead_ctx->remaining_buffered_len = 0;

	if (key_identifier->s_id) {
		aead_ctx->opaque_key = true;
	} else {
		aead_ctx->ele_ctx = op_args->context;
		aead_ctx->ele_ctx_size = op_args->context_size;
	}

	aead_ctx->op_type_id = args->op_type_id;
	aead_ctx->ele_cipher_handle = cipher_hdl;
	aead_ctx->ele_aead_algo = op_args->ae_algo;
	op_context->subsystem_context = aead_ctx;
	op_context->op_state = CTX_OP_STATE_INIT;

	smw_crypto_set_ctx_subsystem_id(op_context, SUBSYSTEM_ID_ELE);

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK && aead_ctx)
		SMW_UTILS_FREE(aead_ctx);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_expected_output_length() - Set expected output len for multipart op
 * @aead_args: Pointer to internal AEAD arguments
 * @aead_ctx: Pointer to AEAD context
 * @subsystem_exp_output: Expected output length from subsystem
 * @implicit_update_exp_output: Expected output from implicit UPDATE
 *
 * UPDATE Operation:
 * - The subsystem may buffer incomplete blocks internally,
 *   so output length may be less than input length.
 * - expected_output_length = subsystem_exp_output (if available)
 *                            OR input_length (as maximum estimate)
 *
 * FINAL Operation:
 * - The output length includes:
 *   1. Remaining buffered bytes from previous UPDATE operations
 *   2. Input provided to FINAL (if any) - will be processed via implicit UPDATE
 *   3. Tag length (if tag is part of output buffer)
 *
 *   expected_output_length = remaining_buffered_len +
 *                            input_length (from FINAL) +
 *                            tag_length (if applicable)
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_INVALID_PARAM     - Invalid parameters or overflow
 */
static int set_expected_output_length(struct smw_crypto_aead_args *args,
				      struct aead_context *aead_ctx,
				      unsigned int subsystem_exp_output,
				      unsigned int implicit_update_exp_output)
{
	int status = SMW_STATUS_OK;
	unsigned int expected_output_len = 0;
	struct crypto_output_params params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	params.op_step = args->op_step;
	params.remaining_buffered_len = aead_ctx->remaining_buffered_len;

	if (args->op_step == SMW_OP_STEP_UPDATE) {
		/*
		 * For UPDATE: use subsystem expected output if available,
		 * otherwise use input length as estimate
		 */
		params.input_len = subsystem_exp_output ?
					   subsystem_exp_output :
					   smw_crypto_get_aead_input_len(args);
	} else if (args->op_step == SMW_OP_STEP_FINAL) {
		params.input_len = implicit_update_exp_output;

		/* For encryption, add tag length if not in dedicated field */
		if (args->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT) {
			if (!smw_crypto_is_aead_tag_field_set(args))
				params.tag_len = ELE_TAG_LEN;
		}
	}

	/* Use common function to calculate expected output length */
	status = ele_calculate_expected_output_len(&params,
						   &expected_output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	set_all_outputs_length(args, expected_output_len);

end:
	SMW_DBG_PRINTF(VERBOSE,
		       "%s returned %d (expected output length = %u)\n",
		       __func__, status, expected_output_len);
	return status;
}

static int aead(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	op_auth_enc_new_args_t op_args = { 0 };
	hsm_hdl_t cipher_hdl = 0;

	enum smw_config_key_type_id key_type_id = 0;
	struct smw_crypto_aead_args *aead_args = args;
	struct smw_keymgr_descriptor *key_desc = &aead_args->key_desc;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Validate IV length for CCM and ChaCha20-Poly1305 */
	status = validate_iv_length(aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Validate tag length */
	status = validate_tag_length(aead_args);
	if (status != SMW_STATUS_OK) {
		(void)set_output_length(aead_args, NULL);
		goto end;
	}

	op_args.iv_in = smw_crypto_get_aead_user_iv(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aead_user_iv_len(aead_args),
			 op_args.iv_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	key_type_id = key_identifier->type_id;

	/* Get ELE algorithm */
	status = set_aead_algo(key_type_id, aead_args->mode_id,
			       &op_args.ae_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set ELE AEAD flags */
	status = set_aead_flags(aead_args, NULL, &op_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set the key parameters */
	status = set_key(aead_args, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Get output length feature */
	if (!smw_crypto_get_aead_output(aead_args)) {
		status = set_output_length(aead_args, NULL);
		goto end;
	}

	status = get_output_data_len(aead_args, &op_args.output_size);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		(void)set_output_length(aead_args, NULL);
		goto end;
	}

	op_args.output = smw_crypto_get_aead_output(aead_args);

	status = get_input_data_len(aead_args, &op_args.input_size);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.input = smw_crypto_get_aead_input(aead_args);

	op_args.aad = smw_crypto_get_aead_aad(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aead_aad_len(aead_args),
			 op_args.aad_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args.tag = smw_crypto_get_aead_tag(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aead_tag_len(aead_args),
			 op_args.tag_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = do_aead(hdl, &cipher_hdl, &op_args, true);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto end;

	if (status == SMW_STATUS_OK)
		status = process_aead_output(aead_args, &op_args, NULL, 0);
	else
		set_all_outputs_length(aead_args, op_args.exp_output_size);

end:
	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && op_args.key)
		SMW_UTILS_FREE(op_args.key);

	/*
	 * SE lib allocates op_args.iv_out and it should be released after the
	 * operation is performed.
	 */
	if (op_args.iv_out)
		SMW_UTILS_FREE(op_args.iv_out);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int aead_init(struct hdl *hdl, struct smw_crypto_aead_args *aead_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	hsm_hdl_t cipher_hdl = 0;
	op_auth_enc_new_args_t op_args = { 0 };
	enum smw_config_key_type_id key_type_id = 0;
	struct smw_op_context *op_context = NULL;
	struct smw_keymgr_descriptor *key_desc = &aead_args->key_desc;
	struct smw_keymgr_identifier *key_identifier = &key_desc->identifier;
	bool open_cipher_service_flow = true;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_crypto_get_aead_init_op_context(aead_args);
	if (!op_context)
		goto end;

	/* Validate IV length for CCM and ChaCha20-Poly1305 */
	status = validate_iv_length(aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	key_type_id = key_identifier->type_id;

	status = set_aead_algo(key_type_id, aead_args->mode_id,
			       &op_args.ae_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set ELE AEAD flags */
	status = set_aead_flags(aead_args, NULL, &op_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.iv_in = smw_crypto_get_aead_user_iv(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aead_user_iv_len(aead_args),
			 op_args.iv_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM) {
		if (SET_OVERFLOW(smw_crypto_get_aead_aad_len(aead_args),
				 op_args.aad_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		if (SET_OVERFLOW(smw_crypto_get_aead_plaintext_len(aead_args),
				 op_args.input_size)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	/* Set the key parameters */
	status = set_key(aead_args, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!key_identifier->s_id) {
		op_args.flags |= HSM_AUTH_ENC_FLAGS_GET_CTX_SIZE;

		status = do_aead(hdl, &cipher_hdl, &op_args,
				 open_cipher_service_flow);
		if (status != SMW_STATUS_OK)
			goto end;

		open_cipher_service_flow = false;

		op_args.context = SMW_UTILS_MALLOC(op_args.exp_output_size);
		if (!op_args.context) {
			status = SMW_STATUS_ALLOC_FAILURE;
			SMW_DBG_PRINTF(ERROR,
				       "ELE AEAD context allocation failure\n");
			goto end;
		}

		op_args.context_size = op_args.exp_output_size;

		/* Remove the GET_CTX_SIZE flag for actual init */
		op_args.flags &= ~HSM_AUTH_ENC_FLAGS_GET_CTX_SIZE;
	}

	status = do_aead(hdl, &cipher_hdl, &op_args, open_cipher_service_flow);
	if (status != SMW_STATUS_OK)
		goto end;

	status = set_aead_context(op_context, aead_args, &op_args, cipher_hdl);

end:
	if (status != SMW_STATUS_OK &&
	    (!op_context || !op_context->subsystem_context)) {
		(void)close_cipher_service(cipher_hdl);

		if (op_args.context)
			SMW_UTILS_FREE(op_args.context);
	}

	if (key_desc->format_id == SMW_KEYMGR_FORMAT_ID_BASE64 && op_args.key)
		SMW_UTILS_FREE(op_args.key);

	/*
	 * SE lib allocates op_args.iv_out and it should be released after the
	 * operation is performed.
	 */
	if (op_args.iv_out)
		SMW_UTILS_FREE(op_args.iv_out);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static int aead_update_aad(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;

	op_auth_enc_new_args_t op_args = { 0 };

	struct smw_crypto_aead_args *aead_args = args;
	struct smw_op_context *op_context = NULL;
	struct aead_context *aead_ctx = NULL;
	bool is_multi_part_supported = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = check_aead_multi_part_support(ele_ctx,
					       &is_multi_part_supported);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!is_multi_part_supported) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		SMW_DBG_PRINTF(ERROR, "%s AEAD multi-part isn't supported.\n",
			       __func__);
		goto end;
	}

	op_context = smw_crypto_get_aead_aad_op_context(aead_args);
	if (!op_context || !op_context->subsystem_context) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	aead_ctx = op_context->subsystem_context;

	op_args.ae_algo = aead_ctx->ele_aead_algo;

	/* Set ELE AEAD flags */
	op_args.flags = HSM_AUTH_ENC_FLAGS_UPDATE_AAD;
	status = set_operation_type_flag(aead_args, aead_ctx, &op_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!aead_ctx->opaque_key) {
		op_args.flags |= HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;
		op_args.context = aead_ctx->ele_ctx;
		op_args.context_size = aead_ctx->ele_ctx_size;
	}

	op_args.aad = smw_crypto_get_aead_aad(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aead_aad_len(aead_args),
			 op_args.aad_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = do_aead(&ele_ctx->hdl, &aead_ctx->ele_cipher_handle, &op_args,
			 false);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * aead_update_common() - Common UPDATE operation handler
 * @hdl: Pointer to ELE subsystem handle
 * @aead_ctx: Pointer to AEAD context
 * @aead_args: Pointer to AEAD arguments
 * @bytes_written: Pointer to store bytes written (can be NULL)
 * @expected_output_len: Pointer to store expected output on error (can be NULL)
 * @is_implicit_update: True if called as implicit UPDATE before FINAL
 *
 * Performs AEAD UPDATE operation for both explicit UPDATE and implicit
 * UPDATE-before-FINAL scenarios.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer too small
 * Other error codes
 */
static int aead_update_common(struct hdl *hdl, struct aead_context *aead_ctx,
			      struct smw_crypto_aead_args *aead_args,
			      unsigned int *bytes_written,
			      unsigned int *expected_output_len,
			      bool is_implicit_update)
{
	int status = SMW_STATUS_OK;
	op_auth_enc_new_args_t op_args = { 0 };
	unsigned int *buffered_len = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (bytes_written)
		*bytes_written = 0;

	if (expected_output_len)
		*expected_output_len = 0;

	op_args.ae_algo = aead_ctx->ele_aead_algo;
	op_args.flags = HSM_AUTH_ENC_FLAGS_UPDATE_DATA;

	if (aead_ctx->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT)
		op_args.flags |= HSM_AUTH_ENC_FLAGS_ENCRYPT;
	else
		op_args.flags |= HSM_AUTH_ENC_FLAGS_DECRYPT;

	if (!aead_ctx->opaque_key) {
		op_args.flags |= HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;
		op_args.context = aead_ctx->ele_ctx;
		op_args.context_size = aead_ctx->ele_ctx_size;
	}

	status = get_input_data_len(aead_args, &op_args.input_size);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.input = smw_crypto_get_aead_input(aead_args);

	status = get_output_data_len(aead_args, &op_args.output_size);
	if (status != SMW_STATUS_OK)
		goto end;

	op_args.output = smw_crypto_get_aead_output(aead_args);

	/* Call UPDATE operation */
	status = do_aead(hdl, &aead_ctx->ele_cipher_handle, &op_args, false);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		if (expected_output_len) {
			/*
			 * For implicit UPDATE (before FINAL):
			 * Use input_size to calculate total expected output for FINAL.
			 * exp_output_size returns only immediate UPDATE output
			 * (e.g., 16 bytes for 24 bytes input), ignoring buffered data.
			 *
			 * For explicit UPDATE:
			 * Use exp_output_size as returned by ELE.
			 */
			if (is_implicit_update)
				*expected_output_len = op_args.input_size;
			else
				*expected_output_len = op_args.exp_output_size;
		}

		goto end;
	} else if (status != SMW_STATUS_OK) {
		goto end;
	}

	if (bytes_written) {
		if (SET_OVERFLOW(op_args.exp_output_size, *bytes_written)) {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}
	}

	if (is_implicit_update) {
		buffered_len = &aead_ctx->remaining_buffered_len;
		status = ele_update_buffered_len(buffered_len,
						 op_args.input_size,
						 op_args.exp_output_size);

	} else {
		/* For explicit UPDATE, process output and set output length */
		status = process_aead_output(aead_args, &op_args, aead_ctx, 0);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * aead_update_before_final() - Perform update operation before final
 * @hdl: Pointer to ELE subsystem handle
 * @aead_ctx: Pointer to AEAD context
 * @aead_args: Pointer to AEAD arguments (contains all needed info)
 * @bytes_written: Pointer to store number of bytes written by update
 * @expected_output_len: Pointer to store expected output if OUTPUT_TOO_SHORT
 *
 * ELE subsystem doesn't accept input for final operations.
 * If final has input, perform update first, then continue with final
 * (without input).
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OUTPUT_TOO_SHORT  - Output buffer too small
 * Other error codes
 */
static int aead_update_before_final(struct hdl *hdl,
				    struct aead_context *aead_ctx,
				    struct smw_crypto_aead_args *aead_args,
				    unsigned int *bytes_written,
				    unsigned int *expected_output_len)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return aead_update_common(hdl, aead_ctx, aead_args, bytes_written,
				  expected_output_len, true);
}

static int aead_update(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_op_context *op_context = NULL;
	struct smw_crypto_aead_args *aead_args = args;
	struct aead_context *aead_ctx = NULL;
	unsigned int expected_output = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_crypto_get_aead_data_op_context(aead_args);
	if (!op_context || !op_context->subsystem_context)
		goto end;

	aead_ctx = op_context->subsystem_context;

	/* Get output length feature */
	if (!smw_crypto_get_aead_output(aead_args)) {
		status = set_output_length(aead_args, aead_ctx);
		goto end;
	}

	status = aead_update_common(hdl, aead_ctx, aead_args, NULL,
				    &expected_output, false);

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT)
		(void)set_expected_output_length(aead_args, aead_ctx,
						 expected_output, 0);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_final(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	op_auth_enc_new_args_t op_args = { 0 };
	struct smw_op_context *op_context = NULL;
	struct smw_crypto_aead_args *aead_args = args;
	struct aead_context *aead_ctx = NULL;
	unsigned int update_output_offset = 0;
	unsigned char *base_output = NULL;
	bool implicit_update_done = false;
	unsigned int tag_offset = 0;
	unsigned int implicit_update_exp_output = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_context = smw_crypto_get_aead_data_op_context(aead_args);
	if (!op_context || !op_context->subsystem_context)
		goto end;

	aead_ctx = op_context->subsystem_context;

	op_args.ae_algo = aead_ctx->ele_aead_algo;

	/* Get output length feature */
	if (!smw_crypto_get_aead_output(aead_args)) {
		status = set_output_length(aead_args, aead_ctx);
		goto end;
	}

	/*
	 * ELE doesn't accept input for final operations. If final has input,
	 * perform update first, then continue with final (without input).
	 */
	if (smw_crypto_get_aead_input_len(aead_args) > 0) {
		SMW_DBG_PRINTF(DEBUG,
			       "Final with input: performing update first\n");

		status = aead_update_before_final(hdl, aead_ctx, aead_args,
						  &update_output_offset,
						  &implicit_update_exp_output);
		if (status != SMW_STATUS_OK)
			goto set_length_and_exit;

		implicit_update_done = true;

		SMW_DBG_PRINTF(DEBUG, "Final output will write at offset %u\n",
			       update_output_offset);
	}

	status = get_output_data_len(aead_args, &op_args.output_size);
	if (status != SMW_STATUS_OK)
		goto set_length_and_exit;

	base_output = smw_crypto_get_aead_output(aead_args);
	op_args.output = base_output;

	/* Set the output offset for final operation after implicit update */
	if (implicit_update_done && base_output) {
		op_args.output = base_output + update_output_offset;

		if (DEC_OVERFLOW(op_args.output_size, update_output_offset)) {
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
			goto set_length_and_exit;
		}
	}

	/* For final after update, clear input (already processed) */
	if (implicit_update_done) {
		op_args.input = NULL;
		op_args.input_size = 0;
	} else {
		status = get_input_data_len(aead_args, &op_args.input_size);
		if (status != SMW_STATUS_OK)
			goto set_length_and_exit;

		op_args.input = smw_crypto_get_aead_input(aead_args);
	}

	/* Set ELE AEAD flags */
	status = set_aead_flags(aead_args, aead_ctx, &op_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Validate tag length */
	status = validate_tag_length(aead_args);
	if (status != SMW_STATUS_OK)
		goto set_length_and_exit;

	/*
	 * For FINAL encryption, set tag pointer on output buffer (if the
	 * tag is part of the output buffer) based on remaining_buffered_len
	 * updated during UPDATE operations.
	 */
	if (aead_ctx->op_type_id == SMW_CONFIG_AEAD_OP_TYPE_ID_ENCRYPT &&
	    !smw_crypto_is_aead_tag_field_set(aead_args)) {
		base_output = smw_crypto_get_aead_output(aead_args);
		/* Tag position starts with remaining buffered bytes */
		tag_offset = aead_ctx->remaining_buffered_len;

		if (implicit_update_done) {
			if (INC_OVERFLOW(tag_offset, update_output_offset)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}

		if (base_output) {
			op_args.tag = base_output + tag_offset;

			/*
			 * FINAL should only write remaining ciphertext bytes
			 * (not including the tag)
			 */
			op_args.output_size = aead_ctx->remaining_buffered_len;
		}
	} else {
		op_args.tag = smw_crypto_get_aead_tag(aead_args);
	}

	if (SET_OVERFLOW(smw_crypto_get_aead_tag_len(aead_args),
			 op_args.tag_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!aead_ctx->opaque_key) {
		op_args.flags |= HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;
		op_args.context = aead_ctx->ele_ctx;
		op_args.context_size = aead_ctx->ele_ctx_size;
	}

	status = do_aead(hdl, &aead_ctx->ele_cipher_handle, &op_args, false);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT)
		goto end;

	if (status == SMW_STATUS_OK) {
		status = process_aead_output(aead_args, &op_args, aead_ctx,
					     update_output_offset);
		goto end;
	}

set_length_and_exit:
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT)
		(void)set_expected_output_length(aead_args, aead_ctx,
						 op_args.exp_output_size,
						 implicit_update_exp_output);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int aead_multi_part(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;
	struct smw_crypto_aead_args *aead_args = args;
	bool is_multi_part_supported = false;

	status = check_aead_multi_part_support(ele_ctx,
					       &is_multi_part_supported);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!is_multi_part_supported) {
		SMW_DBG_PRINTF(ERROR, "%s AEAD multi-part isn't supported.\n",
			       __func__);
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	switch (aead_args->op_step) {
	case SMW_OP_STEP_INIT:
		status = aead_init(&ele_ctx->hdl, aead_args);
		break;

	case SMW_OP_STEP_UPDATE:
		status = aead_update(&ele_ctx->hdl, aead_args);
		break;

	case SMW_OP_STEP_FINAL:
		status = aead_final(&ele_ctx->hdl, aead_args);
		break;

	default:
		break;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_aead_handle(struct subsystem_context *ele_ctx,
		     enum operation_id operation_id, void *args, int *status)
{
	SMW_DBG_PRINTF(VERBOSE, "Executing %s\n", __func__);

	switch (operation_id) {
	case OPERATION_ID_AEAD:
		*status = aead(&ele_ctx->hdl, args);
		break;

	case OPERATION_ID_AEAD_MULTI_PART:
		*status = aead_multi_part(ele_ctx, args);
		break;

	case OPERATION_ID_AEAD_UPDATE_AAD:
		*status = aead_update_aad(ele_ctx, args);
		break;

	default:
		return false;
	}

	return true;
}

void ele_free_aead_context(struct smw_op_context *ctx)
{
	struct aead_context *aead_ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (ctx && ctx->subsystem_context) {
		aead_ctx = ctx->subsystem_context;

		if (aead_ctx && aead_ctx->ele_ctx) {
			(void)close_cipher_service(aead_ctx->ele_cipher_handle);

			SMW_UTILS_FREE(aead_ctx->ele_ctx);
		}
	}
}

int ele_copy_aead_context(struct smw_op_context *src_ctx,
			  struct smw_op_context *dst_ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct aead_context *src_aead_ctx = NULL;
	struct aead_context *dst_aead_ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!src_ctx || !dst_ctx)
		goto end;

	src_aead_ctx = src_ctx->subsystem_context;
	if (!src_aead_ctx)
		goto end;

	if (src_aead_ctx->opaque_key) {
		/*
		 * Copy context operation is not supported for AEAD multi-part operation
		 * with opaque keys: Opaque key operations require a cipher handle
		 * managed by the ELE FW. We store this handle in the subsystem specific
		 * context (aead_context.ele_cipher_handle) for use in subsequent
		 * multi-part operations. The handle is closed upon operation completion
		 * or error. Once a handle is closed,  it cannot be reused, and
		 * ELE does not provide a mechanism to copy a cipher handle. Therefore,
		 * we cannot duplicate the operation context for opaque key AEAD
		 * operations.
		 */
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		SMW_DBG_PRINTF(ERROR,
			       "Cannot copy AEAD multipart ctx with opaque key");

		goto end;
	}

	dst_aead_ctx = SMW_UTILS_MALLOC(sizeof(*dst_aead_ctx));
	if (!dst_aead_ctx) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	dst_aead_ctx->iv_len = src_aead_ctx->iv_len;
	if (dst_aead_ctx->iv_len)
		SMW_UTILS_MEMCPY(dst_aead_ctx->iv, src_aead_ctx->iv,
				 src_aead_ctx->iv_len);

	dst_aead_ctx->ele_ctx = NULL;
	dst_aead_ctx->ele_ctx_size = 0;
	dst_aead_ctx->ele_aead_algo = src_aead_ctx->ele_aead_algo;
	dst_aead_ctx->opaque_key = src_aead_ctx->opaque_key;
	dst_aead_ctx->remaining_buffered_len =
		src_aead_ctx->remaining_buffered_len;
	dst_aead_ctx->ele_cipher_handle = src_aead_ctx->ele_cipher_handle;
	dst_aead_ctx->op_type_id = src_aead_ctx->op_type_id;

	if (src_aead_ctx->ele_ctx_size && src_aead_ctx->ele_ctx) {
		dst_aead_ctx->ele_ctx =
			SMW_UTILS_MALLOC(src_aead_ctx->ele_ctx_size);
		if (!dst_aead_ctx->ele_ctx) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(dst_aead_ctx->ele_ctx, src_aead_ctx->ele_ctx,
				 src_aead_ctx->ele_ctx_size);

		dst_aead_ctx->ele_ctx_size = src_aead_ctx->ele_ctx_size;
	}

	dst_ctx->subsystem_context = dst_aead_ctx;

	status = SMW_STATUS_OK;

end:
	if (status != SMW_STATUS_OK && dst_aead_ctx) {
		if (dst_aead_ctx->ele_ctx)
			SMW_UTILS_FREE(dst_aead_ctx->ele_ctx);

		SMW_UTILS_FREE(dst_aead_ctx);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_cancel_aead_op(struct smw_op_context *ctx)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_auth_enc_new_args_t op_args = { 0 };
	struct aead_context *aead_ctx = ctx->subsystem_context;

	if (!aead_ctx)
		goto end;

	op_args.flags = HSM_AUTH_ENC_FLAGS_ABORT;
	if (!aead_ctx->opaque_key) {
		op_args.flags |= HSM_AUTH_ENC_FLAGS_PLAINTEXT_KEY;
		op_args.context = aead_ctx->ele_ctx;
		op_args.context_size = aead_ctx->ele_ctx_size;
	}

	op_args.ae_algo = aead_ctx->ele_aead_algo;

	status = do_aead(NULL, &aead_ctx->ele_cipher_handle, &op_args, false);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
