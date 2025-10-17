// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>
#include <smw/crypto/asymmetric_encryption.h>

#include "util.h"
#include "util_attr.h"
#include "util_asymm_encryption.h"

#include "key.h"
#include "asymmetric_encryption.h"

/**
 * get_output_buffer_len() - Return output buffer length
 * @key_desc: Pointer to key descriptor
 *
 * For RSA asymmetric operations:
 * - Encryption: Output buffer size equals key's security size in bytes
 * - Decryption: Output buffer size is ≤ key's security size in bytes
 *               (depends on padding)
 *
 * To ensure adequate output buffer size for both operations, allocate the
 * full security size of the key.
 *
 * Return:
 * Output buffer length in bytes.
 * 0 if key type not supported.
 */
static unsigned int get_output_buffer_len(struct smw_key_descriptor *key_desc)
{
	unsigned int output_buffer_len = 0;

	if (key_desc->type_name == SMW_KEY_TYPE_NAME_NONE &&
	    smw_get_key_type_name(key_desc) != SMW_STATUS_OK)
		goto end;

	if (!key_desc->security_size &&
	    smw_get_security_size(key_desc) != SMW_STATUS_OK)
		goto end;

	if (key_desc->type_name == SMW_KEY_TYPE_NAME_RSA)
		output_buffer_len = BITS_TO_BYTES_SIZE(key_desc->security_size);

end:
	return output_buffer_len;
}

/**
 * set_asymm_encrypt_decrypt_bad_args() - Set asymmetric encryption bad args
 * @subtest: Subtest data.
 * @args: SMW asymmetric encryption arguments.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
static int
set_asymm_encrypt_decrypt_bad_args(struct subtest_data *subtest,
				   struct smw_asymmetric_encryption_args **args)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!subtest || !args)
		return ERR_CODE(BAD_ARGS);

	ret = util_read_test_error(&error, subtest->params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case KEY_DESC_NULL:
		(*args)->key_descriptor = NULL;
		break;

	case KEY_BUFFER_NULL:
		if ((*args)->key_descriptor)
			(*args)->key_descriptor->buffer = NULL;

		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

/**
 * set_output_params() - Set output related parameters
 * @subtest: Subtest data
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @args: SMW asymmetric encryption arguments.
 *
 * Case 1: Only expected_output_len defined
 *         - Set args->output = NULL to query required length
 *
 * Case 2: expected_output buffer defined
 *         - Allocate args->output buffer with expected length
 *
 * Case 3: Neither expected_output nor expected_output_len defined
 *         - Call get_output_buffer_len() to determine required size
 *         - Allocate args->output buffer accordingly
 *
 * Return:
 * PASSED                   - Success
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * -BAD_ARGS                - One of the argument is bad
 * Error code from util_read_hex_buffer
 */
static int set_output_params(struct subtest_data *subtest,
			     unsigned char **expected_output,
			     unsigned int *expected_out_len,
			     struct smw_asymmetric_encryption_args *args)
{
	int res = ERR_CODE(PASSED);

	/* Read expected output buffer */
	res = util_read_hex_buffer(expected_output, expected_out_len,
				   subtest->params, OUTPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read output buffer");
		return res;
	}

	/* Output length is not set by definition file */
	if (res == ERR_CODE(MISSING_PARAMS) ||
	    (is_api_test(subtest) && !*expected_out_len && *expected_output)) {
		if (!args->key_descriptor)
			return ERR_CODE(BAD_ARGS);

		args->output_length =
			get_output_buffer_len(args->key_descriptor);
	} else {
		args->output_length = *expected_out_len;
	}

	/* Get output length feature */
	if (res == ERR_CODE(PASSED) && !*expected_output && *expected_out_len) {
		args->output = NULL;
		args->output_length = 0;
	}

	if (args->output_length) {
		args->output =
			calloc(1, args->output_length * sizeof(*args->output));
		if (!args->output)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		/*
		 * Specific error case where output pointer is set and output
		 * length not
		 */
		if (is_api_test(subtest) && !*expected_out_len &&
		    *expected_output)
			args->output_length = 0;
	}

	return ERR_CODE(PASSED);
}

static int set_key_desc(struct subtest_data *subtest,
			struct smw_asymmetric_encryption_args *args,
			struct keypair_ops *key,
			struct smw_keypair_buffer *key_buffer,
			bool is_encrypt_op)
{
	int res = ERR_CODE(PASSED);

	const char *key_name = NULL;

	args->key_descriptor = &key->desc;

	/* Get the Key name - Mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD Key name");
		res = ERR_CODE(MISSING_PARAMS);
		goto end;
	}

	/* Initialize key descriptor */
	res = key_desc_init(key, key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read the json-c key description */
	if (is_encrypt_op)
		res = read_public_key_descriptor(list_keys(subtest), key,
						 key_name);
	else
		res = key_read_descriptor(list_keys(subtest), key, key_name);

	if (res != ERR_CODE(PASSED))
		goto end;

	if (key_is_id_set(key))
		key_free_key(key);

	if (!key_is_id_set(key) && !is_api_test(subtest) &&
	    (!key_is_type_set(key) || !key_is_security_set(key) ||
	     (is_encrypt_op && !key_is_public_key_defined(key)) ||
	     (!is_encrypt_op && !key_is_private_key_defined(key)))) {
		DBG_PRINT_MISS_PARAM("Key description");
		res = ERR_CODE(MISSING_PARAMS);
	}

end:
	return res;
}

static int compare_output(unsigned char *output, unsigned int output_len,
			  unsigned char *exp_output,
			  unsigned int exp_output_len)
{
	int res = ERR_CODE(PASSED);

	if (!exp_output_len)
		goto exit;

	/* Validate get output length feature */
	if (!output) {
		if (output_len != exp_output_len) {
			DBG_PRINT("Bad output length got %d expected %d",
				  output_len, exp_output_len);
			res = ERR_CODE(SUBSYSTEM);
		}

		goto exit;
	}

	/* Optional output buffer comparison */
	if (exp_output)
		res = util_compare_buffers(output, output_len, exp_output,
					   exp_output_len);

exit:
	return res;
}

int asymmetric_encrypt(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_asymmetric_encryption_args args = { 0 };
	struct smw_asymmetric_encryption_args *pub_args = &args;

	int enc_id = INT_MAX;
	unsigned int output_length = 0;
	unsigned int exp_output_len = 0;
	unsigned char *output = NULL;
	unsigned char *exp_output = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;

	res = set_key_desc(subtest, &args, &key_test, &key_buffer, true);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Read asymmetric encryption attributes */
	res = util_attr_read_attributes(subtest->params, ENC_ATTR_OBJ,
					&algorithm_callback, &args.algo);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Read input buffer */
	res = util_read_hex_buffer(&args.input, &args.input_length,
				   subtest->params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* Read salt buffer */
	res = util_read_hex_buffer(&args.salt, &args.salt_length,
				   subtest->params, SALT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* Get 'enc_id' parameter */
	res = util_read_json_type(&enc_id, ENC_ID_OBJ, t_int, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (enc_id != INT_MAX) {
		res = util_asymm_enc_find_node(list_encrypted_texts(subtest),
					       enc_id, &output, &output_length);
		/* 'enc_id' must not be in the encrypted_texts linked list */
		if (res == ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(ENC_ID_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto exit;
		}
	}

	/* Read expected output buffer */
	res = set_output_params(subtest, &exp_output, &exp_output_len, &args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_asymm_encrypt_decrypt_bad_args(subtest, &pub_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	subtest->smw_status = smw_asymmetric_encrypt(pub_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("Buffer too short, expected %u",
				  args.output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (enc_id != INT_MAX) {
		/* Store encrypted data */
		res = util_asymm_enc_add_node(list_encrypted_texts(subtest),
					      enc_id, args.output,
					      args.output_length);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	res = compare_output(args.output, args.output_length, exp_output,
			     exp_output_len);

exit:
	key_free_key(&key_test);

	if (args.input)
		free(args.input);

	if (args.salt)
		free(args.salt);

	if (enc_id == INT_MAX && args.output)
		free(args.output);

	if (exp_output)
		free(exp_output);

	return res;
}

int asymmetric_decrypt(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_asymmetric_encryption_args args = { 0 };
	struct smw_asymmetric_encryption_args *pub_args = &args;

	int enc_id = INT_MAX;
	unsigned int exp_output_len = 0;
	unsigned char *exp_output = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;

	res = set_key_desc(subtest, &args, &key_test, &key_buffer, false);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Asymmetric encryption attributes */
	res = util_attr_read_attributes(subtest->params, ENC_ATTR_OBJ,
					&algorithm_callback, &args.algo);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Read salt buffer */
	res = util_read_hex_buffer(&args.salt, &args.salt_length,
				   subtest->params, SALT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* Get 'enc_id' parameter */
	res = util_read_json_type(&enc_id, ENC_ID_OBJ, t_int, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (enc_id != INT_MAX) {
		res = util_asymm_enc_find_node(list_encrypted_texts(subtest),
					       enc_id, &args.input,
					       &args.input_length);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(ENC_ID_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto exit;
		}
	} else {
		/* Read input buffer */
		res = util_read_hex_buffer(&args.input, &args.input_length,
					   subtest->params, INPUT_OBJ);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
			goto exit;
	}

	res = set_output_params(subtest, &exp_output, &exp_output_len, &args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_asymm_encrypt_decrypt_bad_args(subtest, &pub_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	subtest->smw_status = smw_asymmetric_decrypt(pub_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("Buffer too short, expected %u",
				  args.output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = compare_output(args.output, args.output_length, exp_output,
			     exp_output_len);

exit:
	key_free_key(&key_test);

	if (args.salt)
		free(args.salt);

	if (enc_id == INT_MAX && args.input)
		free(args.input);

	if (args.output)
		free(args.output);

	if (exp_output)
		free(exp_output);

	return res;
}
