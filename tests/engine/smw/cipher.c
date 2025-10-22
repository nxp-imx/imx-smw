// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2025 NXP
 */

#include <string.h>

#include <json.h>

#include <smw/names.h>
#include <smw_keymgr.h>
#include <smw_crypto.h>

#include "util.h"
#include "util_context.h"
#include "util_cipher.h"

#include "key.h"
#include "cipher.h"

#define ONESHOT 0
#define INIT	1
#define UPDATE	2
#define FINAL	3

#define CIPHER_MODE(_name)                                                     \
	{                                                                      \
		.name = SMW_CIPHER_MODE_NAME_##_name, .string = #_name         \
	}

static struct {
	smw_cipher_mode_t name;
	const char *string;
} cipher_mode_names[] = { CIPHER_MODE(CBC), CIPHER_MODE(CFB), CIPHER_MODE(CTR),
			  CIPHER_MODE(CTS), CIPHER_MODE(ECB), CIPHER_MODE(XTS),
			  CIPHER_MODE(OFB) };

#define CIPHER_OP_TYPE(_name)                                                  \
	{                                                                      \
		.name = SMW_CIPHER_OP_TYPE_NAME_##_name, .string = #_name      \
	}

static struct {
	smw_cipher_op_type_t name;
	const char *string;
} cipher_op_type_names[] = { CIPHER_OP_TYPE(ENCRYPT), CIPHER_OP_TYPE(DECRYPT) };

smw_cipher_mode_t cipher_get_mode_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_CIPHER_MODE_NAME_NONE;

	for (; i < ARRAY_SIZE(cipher_mode_names); i++) {
		if (!strcmp(cipher_mode_names[i].string, string))
			return cipher_mode_names[i].name;
	}

	return SMW_CIPHER_MODE_NAME_NB + 1;
}

smw_cipher_op_type_t cipher_get_op_type_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_CIPHER_OP_TYPE_NAME_NONE;

	for (; i < ARRAY_SIZE(cipher_op_type_names); i++) {
		if (!strcmp(cipher_op_type_names[i].string, string))
			return cipher_op_type_names[i].name;
	}

	return SMW_CIPHER_OP_TYPE_NAME_NB + 1;
}

/**
 * cipher_bad_params() - Set cipher bad parameters
 * @params: JSON Cipher parameters.
 * @oneshot: SMW cipher one-shot arguments.
 * @init: SMW cipher initialization arguments.
 * @data: SMW cipher data arguments.
 * @step: Operation step define value
 *
 * Return:
 * PASSED		- Success.
 * -BAD_PARAM_TYPE	- Test error is not supported.
 * -BAD_ARGS		- One of the argument is bad.
 */
static int cipher_bad_params(struct json_object *params,
			     struct smw_cipher_args **oneshot,
			     struct smw_cipher_init_args **init,
			     struct smw_cipher_data_args **data,
			     unsigned int step)
{
	int ret = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!params || (step == ONESHOT && (!oneshot || !init)) ||
	    (step == INIT && !init) ||
	    ((step == UPDATE || step == FINAL) && !data))
		return ret;

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		if (step == ONESHOT)
			*oneshot = NULL;
		else if (step == INIT)
			*init = NULL;
		else if (step == UPDATE || step == FINAL)
			*data = NULL;

		break;

	case KEY_DESC_NULL:
		(*init)->keys_desc = NULL;
		break;

	case KEY_BUFFER_NULL:
		if (!(*init)->keys_desc) {
			DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
			ret = ERR_CODE(BAD_PARAM_TYPE);
			break;
		}

		(*init)->keys_desc[0]->buffer = NULL;
		break;

	case CTX_NULL:
		if (step == INIT)
			(*init)->context = NULL;
		else if (step == UPDATE || step == FINAL)
			(*data)->context = NULL;

		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

/**
 * cipher_update_save_out_data() - Save intermediate output data
 * @subtest: Subtest data
 * @cipher_args: SMW cipher update arguments
 * @ctx_id: Local context ID
 *
 * If 'save_output' JSON parameter is set to true, output data from a cipher
 * update operation is saved in the cipher output data linked list.
 *
 * Return:
 * PASSED		- Success
 * -BAD_PARAM_TYPE	- JSON parameter incorrectly set
 * Error code from util_cipher_add_out_data
 */
static int cipher_update_save_out_data(struct subtest_data *subtest,
				       struct smw_cipher_data_args *cipher_args,
				       unsigned int ctx_id)
{
	int res = ERR_CODE(PASSED);
	bool save_flag = false;

	res = util_read_json_type(&save_flag, SAVE_OUT_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	if (save_flag)
		res = util_cipher_add_out_data(list_ciphers(subtest), ctx_id,
					       cipher_args->output,
					       cipher_args->output_length);

	return res;
}

/**
 * set_init_params() - Set cipher initialization parameters
 * @subtest: Subtest data
 * @args: Pointer to SMW cipher initialization API arguments
 * @keys: Pointer to internal cipher keys structure
 *
 * Return:
 * PASSED	- Success
 * Error code from util_read_hex_buffer
 * Error code from key_read_descriptors
 */
static int set_init_params(struct subtest_data *subtest,
			   struct smw_cipher_init_args *args, struct keys *keys)
{
	int res = ERR_CODE(PASSED);
	const char *mode_string = NULL;
	const char *op_type_string = NULL;

	args->subsystem_name = subtest->subsystem;

	/* Get cipher mode */
	res = util_read_json_type(&mode_string, MODE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Cipher mode");
		return ERR_CODE(MISSING_PARAMS);
	}

	args->mode_name = cipher_get_mode_name(mode_string);

	/* Get the operation type */
	res = util_read_json_type(&op_type_string, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Cipher operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	args->op_type_name = cipher_get_op_type_name(op_type_string);

	/* Read IV buffer if any */
	res = util_read_hex_buffer(&args->iv, &args->iv_length, subtest->params,
				   IV_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read IV buffer");
		return res;
	}

	/* Set key descriptors */
	res = key_read_descriptors(subtest, KEY_NAME_OBJ, &args->nb_keys,
				   &args->keys_desc, keys);
	if (res == ERR_CODE(VALUE_NOTFOUND) && is_api_test(subtest))
		res = ERR_CODE(PASSED);

	return res;
}

/**
 * set_output_params() - Set cipher output related parameters
 * @subtest: Subtest data
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @args: Pointer to SMW cipher data API arguments
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_output_params(struct subtest_data *subtest,
			     unsigned char **expected_output,
			     unsigned int *expected_out_len,
			     struct smw_cipher_data_args *args)
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
		/* Set a value large enough (input + AES block size):
		 * In case of final operation, if previous cipher update
		 * operation was not a cipher block size modulus, ensure that
		 * the final output buffer can contain the input data block + a
		 * cipher block.
		 * Use the biggest cipher block size which is AES block of 16
		 * bytes
		 */
		args->output_length = args->input_length + 16;
	} else {
		args->output_length = *expected_out_len;
	}

	/* If length is set to 0 by definition file output pointer is NULL */
	if (args->output_length) {
		args->output = malloc(args->output_length);
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

int cipher(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	struct smw_cipher_args args = { 0 };
	struct smw_cipher_args *cipher_args = &args;
	struct smw_cipher_init_args *init = &args.init;
	struct keys keys = { 0 };
	unsigned int cipher_id = UINT_MAX;
	bool encrypt_op = false;
	bool decrypt_op = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.init.version = subtest->version;
	args.data.version = subtest->version;

	res = set_init_params(subtest, init, &keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Get operation type */
	encrypt_op = (init->op_type_name == SMW_CIPHER_OP_TYPE_NAME_ENCRYPT);
	decrypt_op = (init->op_type_name == SMW_CIPHER_OP_TYPE_NAME_DECRYPT);

	/* Get 'cipher_id' parameter, if any */
	res = util_read_json_type(&cipher_id, CIPHER_ID_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	/* Try to get saved data if 'cipher_id' is set */
	if (cipher_id != UINT_MAX) {
		res = util_cipher_find_node(list_ciphers(subtest), cipher_id,
					    &args.data.input,
					    &args.data.input_length);

		if ((encrypt_op && res == ERR_CODE(PASSED)) ||
		    (decrypt_op && res != ERR_CODE(PASSED))) {
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
	if (decrypt_op)
		res = util_read_decryption_input_buffer(subtest,
							&args.data.input,
							&args.data.input_length,
							cipher_id, INPUT_OBJ);
	else
		res = util_read_hex_buffer(&args.data.input,
					   &args.data.input_length,
					   subtest->params, INPUT_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_output_params(subtest, &expected_output, &expected_out_len,
				&args.data);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(subtest->params, &cipher_args, &init, NULL,
				ONESHOT);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_cipher(cipher_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("Buffer too short, expected %u",
				  cipher_args->data.output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	} else if (!cipher_args->data.output) {
		/* Case when the output length is requested */
		if (cipher_args->data.output_length !=
		    cipher_args->data.input_length) {
			DBG_PRINT("Invalid output length, got %u expected %u",
				  cipher_args->data.output_length,
				  cipher_args->data.input_length);
			res = ERR_CODE(API_STATUS_NOK);
			goto end;
		}
	}

	if (encrypt_op && cipher_id != UINT_MAX) {
		/*
		 * In case of encryption, if 'cipher_id' is set, save the
		 * ciphertext to the ciphers list.
		 */
		res = util_cipher_add_out_data(list_ciphers(subtest), cipher_id,
					       cipher_args->data.output,
					       cipher_args->data.output_length);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	/* Optional output comparison */
	if (args.data.output && expected_output)
		res = util_compare_buffers(args.data.output,
					   args.data.output_length,
					   expected_output, expected_out_len);

end:
	if (args.data.input && (encrypt_op || cipher_id == UINT_MAX))
		free(args.data.input);

	if (args.init.iv)
		free(args.init.iv);

	if (expected_output)
		free(expected_output);

	if (args.data.output)
		free(args.data.output);

	free_keys(&keys);

	return res;
}

int cipher_init(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	enum smw_status_code smw_status = SMW_STATUS_OK;
	unsigned int ctx_id = UINT_MAX;
	struct smw_cipher_init_args args = { 0 };
	struct smw_cipher_init_args *cipher_args = &args;
	struct smw_context_args ctx_args = { 0 };
	struct keys keys = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (is_api_test(subtest)) {
		subtest->smw_status = smw_allocate_context(&ctx_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto end;
		}
	}

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context,
				      ctx_args.context);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = set_init_params(subtest, cipher_args, &keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(subtest->params, NULL, &cipher_args, NULL,
				INIT);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_cipher_init(cipher_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);

		if (!args.context) {
			res = util_context_update_node(list_op_ctxs(subtest),
						       ctx_id, args.context);
			if (res != ERR_CODE(PASSED))
				DBG_PRINT("Failed to update context node data");
		}
	}

end:
	if (is_api_test(subtest)) {
		smw_status = smw_cancel_operation(&ctx_args);
		if (subtest->smw_status == SMW_STATUS_OK &&
		    smw_status != SMW_STATUS_OK) {
			subtest->smw_status = smw_status;
			res = ERR_CODE(API_STATUS_NOK);
		}
	}

	if (args.iv)
		free(args.iv);

	free_keys(&keys);

	return res;
}

int cipher_update(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	struct smw_cipher_data_args args = { 0 };
	struct smw_cipher_data_args *cipher_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input buffer. Could not be set for API tests only */
	res = util_read_hex_buffer(&args.input, &args.input_length,
				   subtest->params, INPUT_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_output_params(subtest, &expected_output, &expected_out_len,
				cipher_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(subtest->params, NULL, NULL, &cipher_args,
				UPDATE);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_cipher_update(cipher_args);

	/*
	 * Save output data if operation success.
	 * Output data is checked at final step
	 */
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);

		if (!args.context) {
			res = util_context_update_node(list_op_ctxs(subtest),
						       ctx_id, args.context);
			if (res != ERR_CODE(PASSED))
				DBG_PRINT("Failed to update context node data");
		}

	} else {
		res = cipher_update_save_out_data(subtest, cipher_args, ctx_id);
	}

end:
	if (args.input)
		free(args.input);

	if (args.output)
		free(args.output);

	if (expected_output)
		free(expected_output);

	return res;
}

int cipher_final(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	struct smw_cipher_data_args args = { 0 };
	struct smw_cipher_data_args *cipher_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input if any */
	res = util_read_hex_buffer(&args.input, &args.input_length,
				   subtest->params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_output_params(subtest, &expected_output, &expected_out_len,
				cipher_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(subtest->params, NULL, NULL, &cipher_args,
				FINAL);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_cipher_final(cipher_args);

	if (!args.context) {
		res = util_context_update_node(list_op_ctxs(subtest), ctx_id,
					       args.context);
		if (res != ERR_CODE(PASSED))
			DBG_PRINT("Failed to update context node data");
	}

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (expected_output) {
		res = util_cipher_add_out_data(list_ciphers(subtest), ctx_id,
					       cipher_args->output,
					       cipher_args->output_length);
		if (res != ERR_CODE(PASSED))
			goto end;

		res = util_cipher_cmp_output_data(list_ciphers(subtest), ctx_id,
						  expected_output,
						  expected_out_len);
	}

end:
	if (args.input)
		free(args.input);

	if (args.output)
		free(args.output);

	if (expected_output)
		free(expected_output);

	return res;
}
