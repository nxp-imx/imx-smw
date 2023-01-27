// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <string.h>

#include <json.h>

#include <smw_keymgr.h>
#include <smw_crypto.h>

#include "cipher.h"
#include "keymgr.h"
#include "util.h"
#include "util_key.h"
#include "util_list.h"
#include "util_context.h"
#include "util_cipher.h"

#define ONESHOT 0
#define INIT	1
#define UPDATE	2
#define FINAL	3

/**
 * struct cipher_keys - Group of structures representing keys
 * @nb_keys: Number of keys
 * @keys_test: Pointer to an array of test keypair structures
 * @keys_desc: Pointer to an array of SMW key descriptor pointers
 * @keys_buffer: Pointer to an array of key buffer
 */
struct cipher_keys {
	unsigned int nb_keys;
	struct keypair_ops *keys_test;
	struct smw_key_descriptor **keys_desc;
	struct smw_keypair_buffer *keys_buffer;
};

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
	int ret;
	enum arguments_test_err_case error;

	if (!params || (step == ONESHOT && (!oneshot || !init)) ||
	    (step == INIT && !init) ||
	    ((step == UPDATE || step == FINAL) && !data))
		return ERR_CODE(BAD_ARGS);

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
		(*init)->keys_desc[0]->buffer = NULL;
		break;

	case CTX_NULL:
		if (step == INIT)
			(*init)->context = NULL;
		else if (step == UPDATE || step == FINAL)
			(*data)->context = NULL;

		break;

	case CTX_HANDLE_NULL:
		(*data)->context->handle = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

/**
 * allocate_keys() - Allocate all fields present in cipher keys structure
 * @keys: Pointer to structure to update
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failure
 */
static int allocate_keys(struct cipher_keys *keys)
{
	struct keypair_ops *keys_test = NULL;
	struct smw_key_descriptor **keys_desc = NULL;
	struct smw_keypair_buffer *keys_buffer = NULL;

	if (!keys->nb_keys)
		return ERR_CODE(INTERNAL);

	/* Allocate keypair ops array */
	keys_test = calloc(1, keys->nb_keys * sizeof(struct keypair_ops));
	if (!keys_test)
		goto err;

	/* Allocate keys descriptor array */
	keys_desc = malloc(keys->nb_keys * sizeof(struct smw_key_descriptor *));
	if (!keys_desc)
		goto err;

	/* Allocate keys buffer array */
	keys_buffer = calloc(1, keys->nb_keys * sizeof(*keys_buffer));
	if (!keys_buffer)
		goto err;

	keys->keys_test = keys_test;
	keys->keys_desc = keys_desc;
	keys->keys_buffer = keys_buffer;

	return ERR_CODE(PASSED);

err:
	if (keys_test)
		free(keys_test);

	if (keys_desc)
		free(keys_desc);

	return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
}

/**
 * free_keys() - Free all fields present in cipher keys structure
 * @keys: Pointer to keys structure
 *
 * Return:
 * none
 */
static void free_keys(struct cipher_keys *keys)
{
	unsigned int i;

	if (keys->keys_desc)
		free(keys->keys_desc);

	for (i = 0; i < keys->nb_keys; i++)
		util_key_free_key(&keys->keys_test[i]);

	if (keys->keys_buffer)
		free(keys->keys_buffer);

	if (keys->keys_test)
		free(keys->keys_test);
}

/**
 * set_keys() - Set cipher keys structure
 * @subtest: Subtest data
 * @args: Pointer to SMW cipher initialization API arguments
 * @keys: Pointer to structure to update
 *
 * This function reads the keys description present in the test definition file
 * and set the keys structure.
 *
 * Return:
 * PASSED		- Success
 * -API_STATUS_NOK      - SMW API Call return error
 * -MISSING_PARAMS	- Mandatory parameters are missing
 * Error code from allocate_keys
 * Error code from util_key_desc_init
 * Error code from util_key_read_descriptor
 */
static int set_keys(struct subtest_data *subtest,
		    struct smw_cipher_init_args *args, struct cipher_keys *keys)

{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int i;
	struct keypair_ops *key_test;
	struct json_object *okey_name = NULL;
	struct json_object *obj = NULL;
	const char *key_name = NULL;

	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED) || res == ERR_CODE(VALUE_NOTFOUND)) {
		args->nb_keys = 1;
	} else if (res == ERR_CODE(BAD_PARAM_TYPE)) {
		res = util_read_json_type(&okey_name, KEY_NAME_OBJ, t_array,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			return res;

		args->nb_keys = json_object_array_length(okey_name);
	}

	/*
	 * If this is API test number of keys = 0, need to allocate
	 * at least one key, else test is failed for other reason.
	 */
	keys->nb_keys = args->nb_keys;
	if (is_api_test(subtest) && keys->nb_keys == 0)
		keys->nb_keys = 1;

	res = allocate_keys(keys);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!keys->keys_test || !keys->keys_desc || !keys->keys_buffer)
		return ERR_CODE(INTERNAL);

	for (i = 0; i < keys->nb_keys; i++) {
		key_test = &keys->keys_test[i];

		/* Initialize key descriptor */
		res = util_key_desc_init(key_test, &keys->keys_buffer[i]);
		if (res != ERR_CODE(PASSED))
			return res;

		if (okey_name) {
			obj = json_object_array_get_idx(okey_name, i);
			if (obj)
				key_name = json_object_get_string(obj);
		}

		if (key_name) {
			res = util_key_read_descriptor(list_keys(subtest),
						       key_test, key_name);

			if (res != ERR_CODE(PASSED))
				return res;

			if (util_key_is_id_set(key_test))
				util_key_free_key(key_test);
		}

		if (!util_key_is_id_set(key_test) && !is_api_test(subtest) &&
		    (!util_key_is_type_set(key_test) ||
		     !util_key_is_security_set(key_test) ||
		     !util_key_is_private_key_defined(key_test))) {
			DBG_PRINT_MISS_PARAM("Key description");
			return ERR_CODE(MISSING_PARAMS);
		}

		key_name = NULL;

		keys->keys_desc[i] = &key_test->desc;
	}

	args->keys_desc = keys->keys_desc;

	return ERR_CODE(PASSED);
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
				       int ctx_id)
{
	int res;
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
 * Error code from set_keys
 */
static int set_init_params(struct subtest_data *subtest,
			   struct smw_cipher_init_args *args,
			   struct cipher_keys *keys)
{
	int res;

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
	res = set_keys(subtest, args, keys);

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
	int res;

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
static int set_op_context(struct subtest_data *subtest, int *ctx_id,
			  struct smw_cipher_data_args *args,
			  struct smw_op_context *api_ctx)
{
	int res;

	/* Context ID is a mandatory parameter except for API tests */
	res = util_read_json_type(ctx_id, CTX_ID_OBJ, t_int, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get operation context */
	if (*ctx_id != -1) {
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
	struct cipher_keys keys = { 0 };

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
	struct smw_op_context *context = NULL;
	struct cipher_keys keys = { 0 };

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

	context = malloc(sizeof(*context));
	if (!context) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	args.context = context;

	/* Specific test cases */
	res = cipher_bad_params(subtest->params, NULL, &cipher_args, NULL,
				INIT);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_cipher_init(cipher_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	/*
	 * Add context in linked list if initialization succeed and test isn't
	 * an API test
	 */
	if (!is_api_test(subtest))
		res = util_context_add_node(list_op_ctxs(subtest), ctx_id,
					    context);

end:
	if (context && res != ERR_CODE(PASSED))
		free(context);

	if (args.iv)
		free(args.iv);

	free_keys(&keys);

	return res;
}

int cipher_update(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	int ctx_id = -1;
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
	int ctx_id = -1;
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
