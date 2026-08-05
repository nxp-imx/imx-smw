// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023, 2025-2026 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "util.h"
#include "util_cipher.h"
#include "util_context.h"

#include "key.h"

#define CIPHER_ALGO(_id)                                                       \
	{                                                                      \
		.name = #_id, .psa_alg_id = PSA_ALG_##_id, .iv_required = true \
	}

#define CIPHER_ALGO_NO_IV(_id)                                                 \
	{                                                                      \
		.name = #_id, .psa_alg_id = PSA_ALG_##_id,                     \
		.iv_required = false                                           \
	}

/**
 * struct cipher_alg_info
 * @name: Cipher algo name.
 * @psa_alg_id: PSA cipher algo id.
 */
static struct cipher_alg_info {
	const char *name;
	psa_algorithm_t psa_alg_id;
	bool iv_required;
} cipher_alg_info[] = { CIPHER_ALGO(CBC_NO_PADDING),
			CIPHER_ALGO(CBC_PKCS7),
			CIPHER_ALGO(CCM),
			CIPHER_ALGO(CFB),
			CIPHER_ALGO(CTR),
			CIPHER_ALGO_NO_IV(ECB_NO_PADDING),
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

static int cipher_save_out_data(struct subtest_data *subtest,
				unsigned int ctx_id, unsigned char *output,
				size_t output_length)
{
	int res = ERR_CODE(PASSED);
	bool save_flag = false;
	unsigned int save_out_length = 0;

	res = util_read_json_type(&save_flag, SAVE_OUT_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	if (SET_OVERFLOW(output_length, save_out_length))
		res = ERR_CODE(INTERNAL);

	if (save_flag)
		res = util_cipher_add_out_data(list_ciphers(subtest), ctx_id,
					       output, save_out_length);

	return res;
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
	unsigned int cipher_id = UINT_MAX;
	bool encrypt_op = false;
	bool decrypt_op = false;
	unsigned char *iv = NULL;
	unsigned int iv_length = 0;
	unsigned char *iv_and_input = NULL;

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

	encrypt_op = (!strcmp(operation_name, OP_TYPE_ENCRYPT_STR));
	decrypt_op = (!strcmp(operation_name, OP_TYPE_DECRYPT_STR));

	res = util_read_json_type(&cipher_id, CIPHER_ID_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (cipher_id != UINT_MAX) {
		res = util_cipher_find_node(list_ciphers(subtest), cipher_id,
					    &iv, &iv_length, &input, &length);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(CIPHER_ID_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto end;
		}
	}

	/*
	 * Read input buffer. Could not be set for API tests only.
	 * If input data buffer is defined in the JSON, use this buffer in the
	 * decryption operation. Even if 'cipher_id' is set, the input data
	 * buffer saved in the list will be not be utilized.
	 */
	res = util_read_hex_buffer(&input, &length, subtest->params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED) &&
	    (res != ERR_CODE(MISSING_PARAMS) || cipher_id == UINT_MAX))
		goto end;

	input_length = length;

	/* For decryption, if IV is specified, prepend it to the input. */
	if (decrypt_op && iv && input) {
		if (INC_OVERFLOW(input_length, iv_length) ||
		    input_length == 0) {
			res = ERR_CODE(INTERNAL);
			goto end;
		}

		iv_and_input = malloc(input_length);
		if (!iv_and_input) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}

		memcpy(iv_and_input, iv, iv_length);
		memcpy(iv_and_input + iv_length, input,
		       input_length - iv_length);

		input = iv_and_input;
	}

	res = set_output_params(subtest, input_length, &expected_output,
				&expected_output_length, &output, &output_size);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (encrypt_op) {
		subtest->psa_status =
			psa_cipher_encrypt(key, alg, input, input_length,
					   output, output_size, &output_length);
	}

	else if (decrypt_op) {
		if (iv_and_input)
			subtest->psa_status =
				psa_cipher_decrypt(key, alg, iv_and_input,
						   input_length, output,
						   output_size, &output_length);
		else
			subtest->psa_status =
				psa_cipher_decrypt(key, alg, (uint8_t *)input,
						   input_length, output,
						   output_size, &output_length);
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

	if (encrypt_op && cipher_id != UINT_MAX) {
		/*
		 * In case of encryption, if 'cipher_id' is set, save the
		 * ciphertext to the ciphers list.
		 */
		res = cipher_save_out_data(subtest, cipher_id, output,
					   output_length);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	/* Optional output comparison */
	if (output && expected_output)
		res = util_compare_buffers(output, output_length,
					   expected_output,
					   expected_output_length);

end:
	if (input && cipher_id == UINT_MAX)
		free(input);

	if (iv_and_input)
		free(iv_and_input);

	if (expected_output)
		free(expected_output);

	if (output)
		free(output);

	return res;
}

static int cipher_abort_op(int error, struct subtest_data *subtest,
			   psa_cipher_operation_t *operation)
{
	int res = ERR_CODE(PASSED);
	bool op_no_abort = false;

	if (error == ERR_CODE(PASSED))
		return res;

	res = util_read_json_type(&op_no_abort, OP_NO_ABORT, t_boolean,
				  subtest->params);

	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		return res;

	if (!op_no_abort)
		(void)psa_cipher_abort(operation);

	return ERR_CODE(PASSED);
}

int cipher_init_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	struct keypair_psa key_test = { 0 };
	psa_key_id_t key = PSA_KEY_ID_NULL;
	const char *key_name = NULL;
	char *mode_name = NULL;
	char *operation_name = NULL;
	struct cipher_alg_info *cipher_alg_info = NULL;
	psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
	struct smw_op_context *op_context = NULL;

	struct tbuffer iv = { 0 };

	bool encrypt_op = false;
	bool decrypt_op = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &op_context, NULL);
	if (res != ERR_CODE(PASSED))
		goto end;

	cipher_op.op_context = op_context;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto end;

	key = key_test.attributes.id;

	if (key_test.data)
		free(key_test.data);

	/* Get cipher mode */
	res = util_read_json_type(&mode_name, MODE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	cipher_alg_info = get_cipher_alg_info(mode_name);
	if (!cipher_alg_info) {
		DBG_PRINT("Unknown cipher mode: %s", mode_name);
		res = ERR_CODE(BAD_ARGS);
		goto end;
	}

	/* Get the operation type */
	res = util_read_json_type(&operation_name, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto end;

	encrypt_op = (!strcmp(operation_name, OP_TYPE_ENCRYPT_STR));
	decrypt_op = (!strcmp(operation_name, OP_TYPE_DECRYPT_STR));

	if (encrypt_op) {
		subtest->psa_status =
			psa_cipher_encrypt_setup(&cipher_op, key,
						 cipher_alg_info->psa_alg_id);
	} else if (decrypt_op) {
		subtest->psa_status =
			psa_cipher_decrypt_setup(&cipher_op, key,
						 cipher_alg_info->psa_alg_id);
	} else {
		DBG_PRINT("Unknown operation type: %s", operation_name);
		res = ERR_CODE(BAD_ARGS);
		goto end;
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex, subtest->params);
	if (res == ERR_CODE(PASSED)) {
		subtest->psa_status =
			psa_cipher_set_iv(&cipher_op, iv.data, iv.length);
		if (subtest->psa_status != PSA_SUCCESS) {
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	}

	res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
				    cipher_op.op_context);
	if (res != ERR_CODE(PASSED))
		goto end;

	if (iv.data)
		res = util_cipher_set_iv(list_ciphers(subtest), ctx_id, iv.data,
					 iv.length);

end:
	if (iv.data)
		free(iv.data);

	tmp_res = cipher_abort_op(res, subtest, &cipher_op);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int cipher_set_iv_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
	struct smw_op_context *op_context = NULL;

	struct tbuffer iv = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &op_context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	cipher_op.op_context = op_context;

	res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	subtest->psa_status = psa_cipher_set_iv(&cipher_op, iv.data, iv.length);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
				    cipher_op.op_context);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_cipher_set_iv(list_ciphers(subtest), ctx_id, iv.data,
				 iv.length);

exit:
	if (iv.data)
		free(iv.data);

	tmp_res = cipher_abort_op(res, subtest, &cipher_op);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int cipher_generate_iv_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
	struct smw_op_context *op_context = NULL;

	struct tbuffer iv = { 0 };
	size_t iv_length = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &op_context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	cipher_op.op_context = op_context;

	res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (iv.data) {
		res = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	iv.data = malloc(iv.length);
	if (!iv.data) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	subtest->psa_status = psa_cipher_generate_iv(&cipher_op, iv.data,
						     iv.length, &iv_length);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	SET_OVERFLOW(iv_length, iv.length);

	res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
				    cipher_op.op_context);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_cipher_set_iv(list_ciphers(subtest), ctx_id, iv.data,
				 iv.length);

exit:
	if (iv.data)
		free(iv.data);

	tmp_res = cipher_abort_op(res, subtest, &cipher_op);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int cipher_update_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int tmp_res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
	struct smw_op_context *op_context = NULL;

	struct tbuffer input = { 0 };
	struct tbuffer output = { 0 };
	size_t output_length = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &op_context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	cipher_op.op_context = op_context;

	res = util_read_json_type(&input, INPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Failed to read input buffer");
		return res;
	}

	if (input.length > UINT_MAX - PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE) {
		res = ERR_CODE(BAD_ARGS);
		goto end;
	}

	res = util_read_json_type(&output, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read output buffer");
		goto end;
	}

	if (res == ERR_CODE(VALUE_NOTFOUND) || !output.length)
		output.length = PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input.length);

	output.data = malloc(output.length);
	if (!output.data) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	subtest->psa_status =
		psa_cipher_update(&cipher_op, input.data, input.length,
				  output.data, output.length, &output_length);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	res = cipher_save_out_data(subtest, ctx_id, output.data, output_length);

end:
	if (input.data)
		free(input.data);

	if (output.data)
		free(output.data);

	tmp_res = cipher_abort_op(res, subtest, &cipher_op);
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int cipher_final_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
	struct smw_op_context *op_context = NULL;

	struct tbuffer output = { 0 };
	size_t output_length = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &op_context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	cipher_op.op_context = op_context;

	res = util_read_json_type(&output, OUTPUT_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read output buffer");
		goto end;
	}

	if (res == ERR_CODE(VALUE_NOTFOUND) || !output.length)
		output.length = PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE;

	output.data = malloc(output.length);
	if (!output.data) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	subtest->psa_status = psa_cipher_finish(&cipher_op, output.data,
						output.length, &output_length);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	res = util_context_update_node(list_op_ctxs(subtest), ctx_id,
				       cipher_op.op_context);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = cipher_save_out_data(subtest, ctx_id, output.data, output_length);

end:
	if (output.data)
		free(output.data);

	return res;
}

int cipher_abort_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
	struct smw_op_context *op_context = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &op_context, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	cipher_op.op_context = op_context;

	subtest->psa_status = psa_cipher_abort(&cipher_op);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		return res;
	}

	res = util_context_update_node(list_op_ctxs(subtest), ctx_id,
				       cipher_op.op_context);

	return res;
}
