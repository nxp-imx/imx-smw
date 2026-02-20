// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdlib.h>

#include <psa/crypto.h>
#include <psa/crypto_sizes.h>

#include "asymmetric_encryption.h"
#include "types.h"
#include "util.h"
#include "util_attr.h"
#include "util_asymm_encryption.h"
#include "key.h"

/**
 * set_input_params() - Set input related parameters
 * @subtest: Subtest data
 * @input: Pointer to input buffer pointer
 * @input_length: Pointer to input buffer length
 * @encryption_op: True for encryption, false for decryption
 * @enc_id: Encryption ID for linking encrypt/decrypt operations
 *
 * For encryption: Read input buffer from INPUT_OBJ
 * For decryption: Get input from enc_id list or read from INPUT_OBJ
 *
 * Return:
 * PASSED                   - Success
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * -BAD_ARGS                - One of the argument is bad
 * -BAD_PARAM_TYPE          - enc_id validation failed
 * Error code from util_read_hex_buffer or util_asymm_enc_find_node
 */
static int set_input_params(struct subtest_data *subtest, unsigned char **input,
			    unsigned int *input_length, bool encryption_op,
			    int enc_id)
{
	int res = ERR_CODE(PASSED);
	struct llist *enc_list = list_encrypted_texts(subtest);

	if (encryption_op) {
		/* For encryption: Read input buffer from INPUT_OBJ */
		res = util_read_hex_buffer(input, input_length, subtest->params,
					   INPUT_OBJ);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
			return res;
	} else {
		/* For decryption: Get input from enc_id or from INPUT_OBJ */
		if (enc_id != INT_MAX) {
			res = util_asymm_enc_find_node(enc_list, enc_id, input,
						       input_length);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(ENC_ID_OBJ);
				return ERR_CODE(BAD_PARAM_TYPE);
			}
		} else {
			res = util_read_hex_buffer(input, input_length,
						   subtest->params, INPUT_OBJ);
			if (res != ERR_CODE(PASSED) &&
			    res != ERR_CODE(MISSING_PARAMS))
				return res;
		}
	}

	return ERR_CODE(PASSED);
}

/**
 * set_output_params() - Set output related parameters
 * @subtest: Subtest data
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @output: Pointer to output buffer pointer (will be allocated)
 * @output_length: Pointer to output buffer length
 * @encrypt_op: True for encryption operation, false for decryption
 * @enc_id: Encryption ID for fetching encrypted data
 *
 * This function handles output buffer allocation for asymmetric
 * encryption/decryption operations. It supports three scenarios:

 * Case 1: Expected output buffer with length defined in test definition
 *         - Reads expected output from OUTPUT_OBJ
 *         - Allocates output buffer with expected output buffer length
 *         - Allows output comparison after operation
 *
 * Case 2: Only expected output length defined in test definition
 *         - Uses expected length for output buffer allocation
 *         - No output comparison will be performed post operation completion
 *
 * Case 3: Expected output without length (OUTPUT_OBJ present but length is 0)
 *         - Uses PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE for encryption for
 *           output buffer allocation
 *         - Uses PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE for decryption for
 *           output buffer allocation
 *         - Sets output_length to 0 to trigger buffer size validation test
 *         - No output comparison will be performed
 *
 * Case 4: No expected output defined (OUTPUT_OBJ missing)
 *         - Uses PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE for encryption
 *         - Uses PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE for decryption
 *         - Allocates maximum possible output buffer
 *         - No output comparison will be performed
 *
 * Return:
 * PASSED                   - Success
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * -BAD_ARGS                - One of the argument is bad
 * -BAD_PARAM_TYPE          - enc_id already exists in encrypted_texts list
 * Error code from util_read_hex_buffer()
 */
static int set_output_params(struct subtest_data *subtest,
			     uint8_t **expected_output,
			     unsigned int *expected_output_len,
			     uint8_t **output, unsigned int *output_length,
			     bool encrypt_op, int enc_id)
{
	int res = ERR_CODE(BAD_PARAM_TYPE);

	if (encrypt_op && enc_id != INT_MAX) {
		res = util_asymm_enc_find_node(list_encrypted_texts(subtest),
					       enc_id, output, output_length);
		/* 'enc_id' must not be in the encrypted_texts linked list */
		if (res == ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(ENC_ID_OBJ);
			return res;
		}
	}

	/* Read expected output buffer */
	res = util_read_hex_buffer(expected_output, expected_output_len,
				   subtest->params, OUTPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read output buffer");
		return res;
	}

	/* Output length is not set by definition file */
	if (res == ERR_CODE(MISSING_PARAMS) ||
	    (!*expected_output_len && *expected_output)) {
		if (encrypt_op)
			*output_length = PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE;
		else
			*output_length = PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE;
	} else {
		*output_length = *expected_output_len;
	}

	if (*output_length) {
		*output = calloc(1, *output_length * sizeof(**output));
		if (!*output)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		/*
		 * Specific error case where output pointer is set and output
		 * length not
		 */
		if (!*expected_output_len && *expected_output)
			*output_length = 0;
	}

	return ERR_CODE(PASSED);
}

int asymmetric_encrypt_decrypt_psa(struct subtest_data *subtest,
				   bool encryption_op)
{
	int res = ERR_CODE(PASSED);
	struct keypair_psa key_test = { 0 };
	const char *key_name = NULL;
	psa_algorithm_t psa_alg_id = PSA_ALG_NONE;
	int enc_id = INT_MAX;
	unsigned int input_length = 0;
	unsigned int output_size = 0;
	unsigned int exp_output_len = 0;
	size_t output_length = 0;
	unsigned int salt_length = 0;
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	unsigned char *exp_output = NULL;
	unsigned char *salt = NULL;
	bool output_stored = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_test.data)
		free(key_test.data);

	/* Read asymmetric encryption attributes */
	res = util_attr_read_attributes(subtest->params, ENC_ATTR_OBJ,
					&algorithm_callback_psa, &psa_alg_id);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = util_read_hex_buffer(&salt, &salt_length, subtest->params,
				   SALT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	res = util_read_json_type(&enc_id, ENC_ID_OBJ, t_int, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = set_input_params(subtest, &input, &input_length, encryption_op,
			       enc_id);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = set_output_params(subtest, &exp_output, &exp_output_len, &output,
				&output_size, encryption_op, enc_id);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (encryption_op)
		subtest->psa_status =
			psa_asymmetric_encrypt(key_test.attributes.id,
					       psa_alg_id, input, input_length,
					       salt, salt_length, output,
					       output_size, &output_length);
	else
		subtest->psa_status =
			psa_asymmetric_decrypt(key_test.attributes.id,
					       psa_alg_id, input, input_length,
					       salt, salt_length, output,
					       output_size, &output_length);

	if (subtest->psa_status != PSA_SUCCESS) {
		if (subtest->psa_status == PSA_ERROR_BUFFER_TOO_SMALL)
			DBG_PRINT("Buffer too short, expected %u",
				  output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (encryption_op && enc_id != INT_MAX) {
		/* Store encrypted data, if encryption ID is set */
		res = util_asymm_enc_add_node(list_encrypted_texts(subtest),
					      enc_id, output, output_length);
		if (res != ERR_CODE(PASSED))
			goto exit;

		output_stored = true;
	}

	/* Optional output comparison */
	if (output && exp_output)
		res = util_compare_buffers(output, output_length, exp_output,
					   exp_output_len);

exit:
	if (salt)
		free(salt);

	if (encryption_op) {
		if (input)
			free(input);

		/* Only free output if it wasn't stored in the list */
		if (!output_stored && output)
			free(output);
	} else {
		if (enc_id == INT_MAX && input)
			free(input);

		if (output)
			free(output);
	}

	if (exp_output)
		free(exp_output);

	return res;
}
