// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "util.h"

#include "key.h"

#define CIPHER_ALGO(_id)                                                       \
	{                                                                      \
		.name = #_id, .psa_alg_id = PSA_ALG_##_id                      \
	}

/**
 * struct cipher_alg_info
 * @name: SMW cipher mdoe name.
 * @psa_alg_id: PSA cipher algo id.
 */
static struct cipher_alg_info {
	const char *name;
	psa_algorithm_t psa_alg_id;
} cipher_alg_info[] = { CIPHER_ALGO(CBC_NO_PADDING),
			CIPHER_ALGO(CBC_PKCS7),
			CIPHER_ALGO(CCM),
			CIPHER_ALGO(CFB),
			CIPHER_ALGO(CTR),
			CIPHER_ALGO(ECB_NO_PADDING),
			CIPHER_ALGO(OFB),
			CIPHER_ALGO(STREAM_CIPHER),
			CIPHER_ALGO(XTS),
			CIPHER_ALGO(NONE),
			{ .name = NULL, .psa_alg_id = PSA_ALG_NONE } };

static struct cipher_alg_info *get_cipher_alg_info(const char *alg_name)
{
	return GET_INFO(alg_name, cipher_alg_info);
}

/**
 * set_output_params() - Set cipher output related parameters
 * @subtest: Subtest data
 * @input_length: Input length
 * @expected_output: Pointer to expected output buffer
 * @expected_output_length: Pointer to expected output buffer length
 * @output: Pointer to output buffer
 * @output_length: Pointer to output buffer length
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_output_params(struct subtest_data *subtest, size_t input_length,
			     uint8_t **expected_output,
			     size_t *expected_output_length, uint8_t **output,
			     size_t *output_length)
{
	int res = ERR_CODE(PASSED);
	unsigned int length = 0;

	/* Read expected output buffer */
	res = util_read_hex_buffer(expected_output, &length, subtest->params,
				   OUTPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read output buffer");
		return res;
	}

	*expected_output_length = length;

	/* Output length is not set by definition file */
	if (res == ERR_CODE(MISSING_PARAMS) ||
	    (!*expected_output_length && *expected_output)) {
		if (input_length >= SIZE_MAX)
			return ERR_CODE(BAD_ARGS);

		/* Set a value large enough */
		*output_length =
			PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length);
	} else {
		*output_length = *expected_output_length;
	}

	/* If length is set to 0 by definition file output pointer is NULL */
	if (*output_length) {
		*output = malloc(*output_length);
		if (!*output)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		/*
		 * Specific error case where output pointer is set and output
		 * length not
		 */
		if (!*expected_output_length && *expected_output)
			*output_length = 0;
	}

	return ERR_CODE(PASSED);
}

int cipher_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	struct keypair_psa key_test = { 0 };
	const char *key_name = NULL;
	char *mode_name = NULL;
	char *operation_name = NULL;
	struct cipher_alg_info *cipher_alg_info = NULL;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	psa_algorithm_t alg = PSA_ALG_NONE;
	uint8_t *input = NULL;
	size_t input_length = 0;
	uint8_t *output = NULL;
	size_t output_size = 0;
	size_t output_length = 0;
	uint8_t *expected_output = NULL;
	size_t expected_output_length = 0;
	unsigned int length = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
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

	key = key_test.attributes.id;

	if (key_test.data)
		free(key_test.data);

	/* Get cipher mode */
	res = util_read_json_type(&mode_name, MODE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	cipher_alg_info = get_cipher_alg_info(mode_name);
	if (!cipher_alg_info) {
		res = ERR_CODE(BAD_ARGS);
		return res;
	}

	alg = cipher_alg_info->psa_alg_id;

	/* Get the operation type */
	res = util_read_json_type(&operation_name, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input buffer. Could not be set for API tests only */
	res = util_read_hex_buffer(&input, &length, subtest->params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto end;

	input_length = length;

	res = set_output_params(subtest, input_length, &expected_output,
				&expected_output_length, &output, &output_size);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (!strcmp(operation_name, "ENCRYPT")) {
		subtest->psa_status =
			psa_cipher_encrypt(key, alg, input, input_length,
					   output, output_size, &output_length);
	}

	else if (!strcmp(operation_name, "DECRYPT")) {
		subtest->psa_status =
			psa_cipher_decrypt(key, alg, (uint8_t *)input,
					   input_length, output, output_size,
					   &output_length);
	} else {
		res = ERR_CODE(BAD_ARGS);
		goto end;
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		if (subtest->psa_status == PSA_ERROR_BUFFER_TOO_SMALL)
			DBG_PRINT("Buffer too short, expected %u",
				  output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	/* Optional output comparison */
	if (output && expected_output)
		res = util_compare_buffers(output, output_length,
					   expected_output,
					   expected_output_length);

end:
	if (input)
		free(input);

	if (expected_output)
		free(expected_output);

	if (output)
		free(output);

	return res;
}
