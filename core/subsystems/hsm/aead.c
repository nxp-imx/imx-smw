// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "aead.h"

#include "common.h"

#define HSM_MAX_IV_LEN	       12
#define HSM_GEN_COUNTER_IV_LEN 4
#define HSM_TAG_LEN	       16

/*
 * AEAD using CCM mode can be achieved by setting AAD = 0 and
 * using function hsm_cipher_one_go().
 * AEAD using GCM mode can be achieved using function hsm_auth_enc() and AAD
 * is supported.
 * Depending on the mode, algorithm to be used for the operation (either
 * hsm_cipher_algo or hsm_aead_algo) is defined.
 */
static const struct {
	enum smw_config_key_type_id key_type_id;
	enum smw_config_aead_mode_id aead_mode_id;
	union {
		hsm_op_auth_enc_algo_t hsm_aead_algo;
		hsm_op_cipher_one_go_algo_t hsm_cipher_algo;
	};
} aead_algos[] = { { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		     .aead_mode_id = SMW_CONFIG_AEAD_MODE_ID_CCM,
		     .hsm_cipher_algo = HSM_CIPHER_ONE_GO_ALGO_AES_CCM },
		   { .key_type_id = SMW_CONFIG_KEY_TYPE_ID_AES,
		     .aead_mode_id = SMW_CONFIG_AEAD_MODE_ID_GCM,
		     .hsm_aead_algo = HSM_AUTH_ENC_ALGO_AES_GCM } };

static int set_aead_algo(enum smw_config_key_type_id key_type_id,
			 enum smw_config_aead_mode_id aead_mode_id,
			 hsm_op_auth_enc_algo_t *aead_algo,
			 hsm_op_cipher_one_go_algo_t *cipher_algo)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;

	for (; i < ARRAY_SIZE(aead_algos); i++) {
		if (key_type_id == aead_algos[i].key_type_id &&
		    aead_mode_id == aead_algos[i].aead_mode_id) {
			if (aead_mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM)
				*cipher_algo = aead_algos[i].hsm_cipher_algo;
			else
				*aead_algo = aead_algos[i].hsm_aead_algo;

			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

#define AEAD_FLAG(_op_type_id)                                                 \
	{                                                                      \
		.smw_op_type_id = SMW_CONFIG_AEAD_OP_ID_##_op_type_id,         \
		.hsm_flags = HSM_AUTH_ENC_FLAGS_##_op_type_id                  \
	}

static const struct {
	enum smw_config_aead_op_type_id smw_op_type_id;
	hsm_op_auth_enc_flags_t hsm_flags;
} aead_flags[] = { AEAD_FLAG(ENCRYPT), AEAD_FLAG(DECRYPT) };

/**
 * set_aead_flags() - Set the HSM AEAD operation flags
 * @aead_args: Pointer to internal AEAD arguments structure
 * @hsm_flags: Pointer to HSM AEAD operation flag
 *
 * This function sets the required HSM AEAD operation flags.
 *
 * Depending on the operation type, either HSM_AUTH_ENC_FLAGS_DECRYPT or
 * HSM_AUTH_ENC_FLAGS_ENCRYPT flag is set.
 *
 * GCM AEAD Encryption:
 * - If the user supplies 4 bytes of the IV (fixed part) data, set flag
 *   HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV to request the firmware to
 *   generate the rest.
 * - If the user doesn't supply the IV, set HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV
 *   flag to request the firmware to generate the full IV.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int set_aead_flags(struct smw_crypto_aead_args *aead_args,
			  hsm_op_auth_enc_flags_t *hsm_flags)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int i = 0;

	for (; i < ARRAY_SIZE(aead_flags); i++) {
		if (aead_args->op_id != aead_flags[i].smw_op_type_id)
			continue;

		*hsm_flags = aead_flags[i].hsm_flags;

		if (aead_args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT &&
		    aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_GCM) {
			if (!smw_crypto_get_iv_len(aead_args))
				*hsm_flags |=
					HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV;
			else if (smw_crypto_get_iv_len(aead_args) ==
				 HSM_GEN_COUNTER_IV_LEN)
				*hsm_flags |=
					HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV;
		}

		status = SMW_STATUS_OK;
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_hsm_expected_encr_output_len() - Return the HSM expected output length
 * @aead_args: Pointer to internal AEAD arguments structure
 * @length: Pointer to output buffer length
 *
 * This function returns the HSM expected output buffer length for encryption
 * operation
 *
 * Encryption:
 * GCM with IV generated (partially or entirely) by FW (iv_len = 4 or 0):
 * output length = ciphertext len + tag len (16 bytes) + IV len (12 bytes)
 *
 * CCM mode (iv_len = 12):
 * output length = ciphertext length + tag len (16 bytes)
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int
get_hsm_expected_encr_output_len(struct smw_crypto_aead_args *aead_args,
				 unsigned int *length)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int iv_len = smw_crypto_get_iv_len(aead_args);
	unsigned int tag_len = smw_crypto_get_tag_len(aead_args);

	*length = smw_crypto_get_input_len(aead_args);

	if (!INC_OVERFLOW(*length, tag_len)) {
		if (aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_GCM &&
		    iv_len < HSM_MAX_IV_LEN) {
			if (INC_OVERFLOW(*length, HSM_MAX_IV_LEN))
				goto end;
		}

		status = SMW_STATUS_OK;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d with output length = %u\n",
		       __func__, status, *length);
	return status;
}

static void set_all_outputs_length(struct smw_crypto_aead_args *args,
				   unsigned int *output_len)
{
	if (args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT) {
		smw_crypto_set_output_iv_len(args, HSM_MAX_IV_LEN);
		smw_crypto_set_tag_len(args, HSM_TAG_LEN);
	}

	smw_crypto_set_output_len(args, *output_len);
}

/**
 * set_output_iv() - Copy the IV buffer to output_iv
 * @args: Pointer to internal AEAD arguments
 * @iv_start_index: Starting index of the IV in the output buffer
 * @output: Pointer to output received from FW
 *
 * CCM Mode - IV generated by user (iv_len = 12):
 * Copy the IV buffer from user IV buffer to output_iv field.
 *
 * GCM Mode - IV generated (partially or fully) by FW (iv_len = 0 or 4):
 * Copy the IV buffer from output buffer to output_iv field.
 *
 * Return:
 * None
 */
static void set_output_iv(struct smw_crypto_aead_args *args,
			  unsigned int iv_start_index, uint8_t *output)
{
	unsigned int iv_len = smw_crypto_get_iv_len(args);
	unsigned char *output_iv = smw_crypto_get_output_iv(args);
	unsigned char *iv = smw_crypto_get_iv(args);

	if (output_iv) {
		if (iv_len < HSM_MAX_IV_LEN)
			SMW_UTILS_MEMCPY(output_iv, &output[iv_start_index],
					 HSM_MAX_IV_LEN);
		else if (iv)
			SMW_UTILS_MEMCPY(output_iv, iv, HSM_MAX_IV_LEN);
	}
}

/**
 * set_encryption_io_params() - Set input and output params
 * @aead_args: Pointer to internal AEAD arguments structure
 * @op_args: Pointer to HSM AEAD operation arguments structure
 * @resized_output: Pointer to resized output buffer
 *
 * This function sets HSM AEAD arguments input, input_size,
 * output and output_size for AEAD encryption operation.
 *
 * This function allocates memory to resized_output, if the user output buffer
 * length is less than HSM expected output length (output buffer length +
 * tag length (if applicable) + IV length (if applicable)).
 *
 * resized_output is released once the AEAD operation is performed.
 *
 * Return:
 * SMW_STATUS_OK               - Success
 * SMW_STATUS_INVALID_PARAM    - Invalid argument parameter
 * SMW_STATUS_OUTPUT_TOO_SHORT - Ouptut buffer is too short
 * SMW_STATUS_ALLOC_FAILURE    - Memory allocation failure
 */
static int set_encryption_io_params(struct smw_crypto_aead_args *aead_args,
				    op_auth_enc_args_t *op_args,
				    unsigned char **resized_output)
{
	int status = SMW_STATUS_OK;

	unsigned int hsm_expected_output_len = 0;
	unsigned int output_len = smw_crypto_get_output_len(aead_args);
	bool dedicated_tag_field_set = smw_crypto_is_tag_field_set(aead_args);
	unsigned int tag_len = smw_crypto_get_tag_len(aead_args);
	unsigned int total_user_output_len = output_len;
	unsigned int exp_total_user_output_len =
		smw_crypto_get_input_len(aead_args);

	status = get_hsm_expected_encr_output_len(aead_args,
						  &hsm_expected_output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	/*
	 * total user output length = user output length + tag
	 * length (if applicable).
	 * expected total user output length = user input length +
	 * tag length (if applicable).
	 */
	if (dedicated_tag_field_set) {
		if (INC_OVERFLOW(total_user_output_len, tag_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		if (INC_OVERFLOW(exp_total_user_output_len, tag_len)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	if (total_user_output_len < exp_total_user_output_len) {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (output_len < hsm_expected_output_len) {
		*resized_output = SMW_UTILS_MALLOC(hsm_expected_output_len *
						   sizeof(**resized_output));
		if (!*resized_output) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		op_args->output = *resized_output;
	} else {
		op_args->output = smw_crypto_get_output(aead_args);
	}

	if (SET_OVERFLOW(hsm_expected_output_len, op_args->output_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_args->input = smw_crypto_get_input(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_input_len(aead_args),
			 op_args->input_size))
		status = SMW_STATUS_INVALID_PARAM;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_decryption_io_params() - Set input and output params
 * @aead_args: Pointer to internal AEAD arguments structure
 * @op_args: Pointer to HSM AEAD operation arguments structure
 * @resized_input: Pointer to resized input buffer
 *
 * This function sets HSM AEAD arguments input, input_size, output
 * and output_size for AEAD decryption operation.
 *
 * This function allocates memory to resized_input, if the
 * tag is set in the dedicated tag field. In this case, input
 * buffer and tag buffer will be copied to resized_input.
 *
 * resized_input is released once the AEAD operation is performed.
 *
 * Return:
 * SMW_STATUS_OK               - Success
 * SMW_STATUS_INVALID_PARAM    - Invalid argument parameter
 * SMW_STATUS_OUTPUT_TOO_SHORT - Ouptut buffer is too short
 * SMW_STATUS_ALLOC_FAILURE    - Memory allocation failure
 */
static int set_decryption_io_params(struct smw_crypto_aead_args *aead_args,
				    op_auth_enc_args_t *op_args,
				    unsigned char **resized_input)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int input_len = smw_crypto_get_input_len(aead_args);
	unsigned int tag_len = smw_crypto_get_tag_len(aead_args);
	unsigned char *input = smw_crypto_get_input(aead_args);
	unsigned char *tag = smw_crypto_get_tag(aead_args);
	unsigned int hsm_expected_input_len = input_len;
	unsigned int hsm_expected_output_len = input_len;
	bool dedicated_tag_field_set = smw_crypto_is_tag_field_set(aead_args);

	if (!input_len || !input)
		goto end;

	if (!dedicated_tag_field_set) {
		if (DEC_OVERFLOW(hsm_expected_output_len, tag_len))
			goto end;
	}

	if (smw_crypto_get_output_len(aead_args) < hsm_expected_output_len) {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	if (SET_OVERFLOW(hsm_expected_output_len, op_args->output_size))
		goto end;

	op_args->output = smw_crypto_get_output(aead_args);

	if (dedicated_tag_field_set) {
		if (!tag || !tag_len)
			goto end;

		if (INC_OVERFLOW(hsm_expected_input_len, tag_len))
			goto end;

		*resized_input = SMW_UTILS_MALLOC(hsm_expected_input_len *
						  sizeof(**resized_input));
		if (!*resized_input) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}

		SMW_UTILS_MEMCPY(*resized_input, input, input_len);
		SMW_UTILS_MEMCPY(*resized_input + input_len, tag, tag_len);

		op_args->input = *resized_input;
		input_len = hsm_expected_input_len;
	} else {
		op_args->input = smw_crypto_get_input(aead_args);
	}

	if (SET_OVERFLOW(input_len, op_args->input_size))
		goto end;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_user_encr_outputs_len() - Calculate output buffers length
 * @args: Pointer to internal AEAD arguments
 * @output_len: Pointer to output buffer length
 *
 * @output_len initially points to the expected output length.
 * This function then modifies the value pointed to by @output_len
 * to user output length after performing calculations based on
 * IV length and tag length.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPERATION_FAILURE - Operation failed
 */
static int set_user_encr_outputs_len(struct smw_crypto_aead_args *args,
				     unsigned int *output_len)
{
	int status = SMW_STATUS_OPERATION_FAILURE;

	if (smw_crypto_get_iv_len(args) < HSM_MAX_IV_LEN) {
		if (DEC_OVERFLOW(*output_len, HSM_MAX_IV_LEN))
			goto end;
	}

	if (smw_crypto_is_tag_field_set(args)) {
		if (DEC_OVERFLOW(*output_len, smw_crypto_get_tag_len(args)))
			goto end;
	}

	set_all_outputs_length(args, output_len);

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * copy_buffers_post_encr() - Copy output, tag, IV buffers from output buffer
 * @received_output: Pointer to output received from FW
 * @args: Pointer to internal AEAD arguments
 * @output_len: Pointer to output buffer length
 * @resized_output: Pointer to resized output buffer
 *
 * @output_len initially points to the expected output length.
 * Update the value pointed to by @output_len to user output length after
 * performing calculations based on IV length and tag length.
 *
 * Copy the output IV buffer, tag(if applicable) and output
 * buffer(if applicable) from received_output if the operation is AEAD
 * encryption.
 *
 * Return:
 * SMW_STATUS_OK                - Success
 * SMW_STATUS_OPERATION_FAILURE - Operation failed
 */
static int copy_buffers_post_encr(uint8_t *received_output,
				  struct smw_crypto_aead_args *args,
				  unsigned int *output_len,
				  unsigned char *resized_output)
{
	int status = SMW_STATUS_OK;

	bool dedicated_tag_field_set = smw_crypto_is_tag_field_set(args);
	unsigned int tag_len = smw_crypto_get_tag_len(args);
	unsigned int iv_start_index = 0;
	unsigned char *tag = smw_crypto_get_tag(args);
	unsigned char *output = smw_crypto_get_output(args);

	status = set_user_encr_outputs_len(args, output_len);
	if (status != SMW_STATUS_OK)
		goto end;

	if (smw_crypto_get_iv_len(args) < HSM_MAX_IV_LEN) {
		iv_start_index = *output_len;

		if (dedicated_tag_field_set) {
			if (INC_OVERFLOW(iv_start_index, tag_len)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto end;
			}
		}
	}

	set_output_iv(args, iv_start_index, received_output);

	if (dedicated_tag_field_set) {
		if (tag && tag_len) {
			SMW_UTILS_MEMCPY(tag, &received_output[*output_len],
					 tag_len);
		} else {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}
	}

	if (resized_output) {
		if (output && *output_len) {
			SMW_UTILS_MEMCPY(output, received_output, *output_len);
		} else {
			status = SMW_STATUS_OPERATION_FAILURE;
			goto end;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * set_output_length() - Set the user output buffer length
 * @args: Pointer to internal AEAD arguments
 *
 * Calculate and set the user output buffer length based on user input buffer
 * length and tag length.
 *
 * Return:
 * SMW_STATUS_OK            - Success
 * SMW_STATUS_INVALID_PARAM - Invalid argument parameter
 */
static int set_output_length(struct smw_crypto_aead_args *aead_args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int output_len = smw_crypto_get_input_len(aead_args);

	if (aead_args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT) {
		if (!smw_crypto_is_tag_field_set(aead_args)) {
			if (INC_OVERFLOW(output_len, HSM_TAG_LEN))
				goto end;
		}
	} else {
		if (!smw_crypto_is_tag_field_set(aead_args)) {
			if (DEC_OVERFLOW(output_len, HSM_TAG_LEN))
				goto end;
		}
	}

	set_all_outputs_length(aead_args, &output_len);

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * fill_cipher_args() - Fill HSM cipher arguments structure
 * @aead_args: Pointer to HSM AEAD operation arguments structure
 * @cipher_args: Pointer to HSM cipher operation arguments structure
 *
 * This function fills the required @cipher_args members from @aead_args.
 *
 * Return:
 * None
 */
static void fill_cipher_args(op_auth_enc_args_t *aead_args,
			     op_cipher_one_go_args_t *cipher_args)
{
	cipher_args->key_identifier = aead_args->key_identifier;
	cipher_args->iv = aead_args->iv;
	cipher_args->iv_size = aead_args->iv_size;

	if (aead_args->flags && HSM_AUTH_ENC_FLAGS_ENCRYPT)
		cipher_args->flags = HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT;

	cipher_args->input = aead_args->input;
	cipher_args->output = aead_args->output;
	cipher_args->input_size = aead_args->input_size;
	cipher_args->output_size = aead_args->output_size;
}

static int aead(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	hsm_err_t err = HSM_NO_ERROR;
	op_auth_enc_args_t op_aead_args = { 0 };
	op_cipher_one_go_args_t op_cipher_args = { 0 };

	struct smw_crypto_aead_args *aead_args = args;
	struct smw_keymgr_descriptor *key_desc = NULL;

	unsigned char *resized_output = NULL;
	unsigned char *resized_input = NULL;
	unsigned int output_length = 0;
	unsigned int iv_length = 0;
	uint8_t *output = NULL;
	bool is_encrypt_op = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	iv_length = smw_crypto_get_iv_len(aead_args);

	/* For AES CCM mode, AAD should be 0, IV len should be 12 */
	if (aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM) {
		if (smw_crypto_get_aad(aead_args))
			goto end;

		if (iv_length != HSM_MAX_IV_LEN) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	/*
	 * For HSM subsystem, tag length must be 16 Bytes.
	 * If tag length < HSM_TAG_LEN, set the required output buffer lengths and
	 * return SMW_STATUS_OUTPUT_TOO_SHORT.
	 * If tag length > HSM_TAG_LEN, HSM returns HSM_INVALID_PARAM
	 * because the output length is too big. So, set the tag length to 16 and
	 * continue with operation.
	 */
	if (smw_crypto_get_tag_len(aead_args) < HSM_TAG_LEN) {
		set_output_length(aead_args);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	} else if (smw_crypto_get_tag_len(aead_args) > HSM_TAG_LEN) {
		smw_crypto_set_tag_len(args, HSM_TAG_LEN);
	}

	if (aead_args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT)
		is_encrypt_op = true;

	key_desc = &aead_args->key_desc;

	if (key_desc->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		// TODO: first import key, then do authenticated encryption
		// Currently, key import is not supported by HSM
		SMW_DBG_PRINTF(VERBOSE,
			       "%s : key import is not supported by HSM\n",
			       __func__);
		goto end;
	}

	/* Set HSM operation algorithm */
	status = set_aead_algo(key_desc->identifier.type_id, aead_args->mode_id,
			       &op_aead_args.ae_algo,
			       &op_cipher_args.cipher_algo);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Set HSM flags */
	status = set_aead_flags(aead_args, &op_aead_args.flags);
	if (status != SMW_STATUS_OK)
		goto end;

	op_aead_args.iv = smw_crypto_get_iv(aead_args);

	if (SET_OVERFLOW(iv_length, op_aead_args.iv_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_aead_args.aad = smw_crypto_get_aad(aead_args);

	if (SET_OVERFLOW(smw_crypto_get_aad_len(aead_args),
			 op_aead_args.aad_size)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	op_aead_args.key_identifier = key_desc->identifier.id;

	/* Get output length feature */
	if (!smw_crypto_get_output(aead_args)) {
		status = set_output_length(aead_args);
		goto end;
	}

	if (is_encrypt_op)
		status = set_encryption_io_params(aead_args, &op_aead_args,
						  &resized_output);
	else
		status = set_decryption_io_params(aead_args, &op_aead_args,
						  &resized_input);

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT)
		(void)set_output_length(aead_args);

	if (status != SMW_STATUS_OK)
		goto end;

	if (aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM) {
		/*
		 * op_cipher_args.cipher_algo is already set. Fill the remaining
		 * required cipher one go operation arguments.
		 */
		fill_cipher_args(&op_aead_args, &op_cipher_args);

		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_cipher_one_go()\n"
			       "cipher_hdl: %d\n"
			       "op_cipher_one_go_args_t\n"
			       "    key_identifier: %d\n"
			       "    iv: %p\n"
			       "    iv_size: %d\n"
			       "    cipher_algo: %d\n"
			       "    flags: %d\n"
			       "    input: %p\n"
			       "    output: %p\n"
			       "    input_size: %d\n"
			       "    output_size: %d\n",
			       __func__, __LINE__, hdl->cipher,
			       op_cipher_args.key_identifier, op_cipher_args.iv,
			       op_cipher_args.iv_size,
			       op_cipher_args.cipher_algo, op_cipher_args.flags,
			       op_cipher_args.input, op_cipher_args.output,
			       op_cipher_args.input_size,
			       op_cipher_args.output_size);

		err = hsm_cipher_one_go(hdl->cipher, &op_cipher_args);
	} else {
		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_auth_enc()\n"
			       "aead_hdl: %d\n"
			       "op_auth_enc_args_t\n"
			       "    key_identifier: %d\n"
			       "    iv: %p\n"
			       "    iv_size: %d\n"
			       "    aad: %p\n"
			       "    aad_size: %d\n"
			       "    ae_algo: %d\n"
			       "    flags: %d\n"
			       "    input: %p\n"
			       "    output: %p\n"
			       "    input_size: %d\n"
			       "    output_size: %d\n",
			       __func__, __LINE__, hdl->cipher,
			       op_aead_args.key_identifier, op_aead_args.iv,
			       op_aead_args.iv_size, op_aead_args.aad,
			       op_aead_args.aad_size, op_aead_args.ae_algo,
			       op_aead_args.flags, op_aead_args.input,
			       op_aead_args.output, op_aead_args.input_size,
			       op_aead_args.output_size);

		err = hsm_auth_enc(hdl->cipher, &op_aead_args);
	}

	if (!is_encrypt_op && err == HSM_GENERAL_ERROR)
		/*
		 * Assume HSM returned this error code
		 * because the tag is invalid.
		 */
		status = SMW_STATUS_SIGNATURE_INVALID;
	else
		status = convert_hsm_err(err);

	if (aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_GCM &&
	    (!SET_OVERFLOW(op_aead_args.output_size, output_length)))
		output = op_aead_args.output;
	else if (aead_args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM &&
		 (!SET_OVERFLOW(op_cipher_args.output_size, output_length)))
		output = op_cipher_args.output;
	else
		status = SMW_STATUS_OPERATION_FAILURE;

	if (is_encrypt_op) {
		if (status == SMW_STATUS_OK && output)
			status = copy_buffers_post_encr(output, aead_args,
							&output_length,
							resized_output);

	} else {
		smw_crypto_set_output_len(aead_args, output_length);
	}

end:
	if (resized_input)
		SMW_UTILS_FREE(resized_input);

	if (resized_output)
		SMW_UTILS_FREE(resized_output);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool hsm_aead_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_AEAD:
		*status = aead(hdl, args);
		break;

	default:
		return false;
	}

	return true;
}
