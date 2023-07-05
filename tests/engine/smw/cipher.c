// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <string.h>

#include <json.h>

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
 * -BAD_PARAM_TYPE	- Test error is not suuported.
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
		if (step == INIT) {
			if ((*init)->context)
				free((*init)->context);

			(*init)->context = NULL;
		} else if (step == UPDATE || step == FINAL) {
			(*data)->context = NULL;
		}

		break;

	case CTX_HANDLE_NULL:
		if (data && (*data) && (*data)->context)
			(*data)->context->handle = NULL;
		else
			ret = ERR_CODE(BAD_ARGS);
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
 * If 'save_output' JSON parameter is set to 1, output data from a cipher update
 * operation is saved in the cipher output data linked list.
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
	int save_flag = 0;

	res = util_read_json_type(&save_flag, SAVE_OUT_OBJ, t_int,
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

	if (subtest->subsystem) {
		if (!strcmp(subtest->subsystem, "DEFAULT"))
			args->subsystem_name = NULL;
		else
			args->subsystem_name = subtest->subsystem;
	}

	/* Get cipher mode */
	res = util_read_json_type(&args->mode_name, MODE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Cipher mode");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get the operation type */
	res = util_read_json_type(&args->operation_name, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Cipher operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

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

/**
 * set_op_context() - Set operation context
 * @params: JSON Cipher parameters
 * @cmn_params: Operation common parameters
 * @ctx_id: Pointer to context ID
 * @args: Pointer to SMW cipher data API arguments
 * @api_ctx: Pointer to API operation context structure
 *
 * Return:
 * PASSED		- Success
 * -MISSING_PARAMS	- Context ID json parameter is missing
 * Error code from util_context_find_node
 */
static int set_op_context(struct subtest_data *subtest, unsigned int *ctx_id,
			  struct smw_cipher_data_args *args,
			  struct smw_op_context *api_ctx)
{
	int res = ERR_CODE(PASSED);

	/* Context ID is a mandatory parameter except for API tests */
	res = util_read_json_type(ctx_id, CTX_ID_OBJ, t_int, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get operation context */
	if (*ctx_id != UINT_MAX) {
		res = util_context_find_node(list_op_ctxs(subtest), *ctx_id,
					     &args->context);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to find context node");
			return res;
		}
	} else {
		/* API specific tests cases */
		args->context = api_ctx;
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

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.init.version = subtest->version;
	args.data.version = subtest->version;

	res = set_init_params(subtest, init, &keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read input buffer. Could not be set for API tests only */
	res = util_read_hex_buffer(&args.data.input, &args.data.input_length,
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
	}

	/* Optional output comparison */
	if (args.data.output && expected_output)
		res = util_compare_buffers(args.data.output,
					   args.data.output_length,
					   expected_output, expected_out_len);

end:
	if (args.data.input)
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
	int ctx_id = -1;
	struct smw_cipher_init_args args = { 0 };
	struct smw_cipher_init_args *cipher_args = &args;
	struct keys keys = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	/* Context ID is a mandatory parameter except for API tests */
	res = util_read_json_type(&ctx_id, CTX_ID_OBJ, t_int, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	args.version = subtest->version;

	res = set_init_params(subtest, cipher_args, &keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	args.context = malloc(sizeof(*args.context));
	if (!args.context) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	/* Specific test cases */
	res = cipher_bad_params(subtest->params, NULL, &cipher_args, NULL,
				INIT);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_cipher_init(cipher_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		free(args.context);
		args.context = NULL;
		goto end;
	}

	/*
	 * Add context in linked list if initialization succeed and test isn't
	 * an API test
	 */
	if (!is_api_test(subtest))
		res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
					    args.context);

end:
	if (res != ERR_CODE(PASSED) && args.context)
		free(args.context);

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
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = set_op_context(subtest, &ctx_id, cipher_args, &api_ctx);
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
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);
	else
		res = cipher_update_save_out_data(subtest, cipher_args, ctx_id);

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
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = set_op_context(subtest, &ctx_id, cipher_args, &api_ctx);
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
