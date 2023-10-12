// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <string.h>

#include <json.h>

#include <smw_keymgr.h>
#include <smw/crypto/aead.h>

#include "util.h"
#include "util_aead.h"
#include "util_context.h"

#include "key.h"
#include "aead.h"

#define AES_BLOCK_SIZE 16

enum cmd { ONESHOT = 0, INIT, UPDATE_ADD, UPDATE, FINAL };

/**
 * aead_bad_params() - Set AEAD bad parameters
 * @params: JSON AEAD parameters
 * @arg: SMW AEAD arguments
 * @key: Key descriptor
 * @context: SMW cryptographic operation context
 * @cmd: AEAD command
 *
 * Return:
 * PASSED		- Success.
 * -BAD_PARAM_TYPE	- Test error is not suuported.
 * -BAD_ARGS		- One of the argument is bad.
 */
static int aead_bad_params(struct json_object *params, void **arg,
			   struct smw_key_descriptor **key,
			   struct smw_op_context **context, enum cmd cmd)
{
	int ret = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!params || !arg)
		return ret;

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*arg = NULL;
		break;

	case KEY_DESC_NULL:
		if (key)
			*key = NULL;

		break;

	case KEY_BUFFER_NULL:
		if (key)
			(*key)->buffer = NULL;

		break;

	case CTX_NULL:
		if (context) {
			if (cmd == INIT)
				free(*context);

			*context = NULL;
		}

		break;

	case CTX_HANDLE_NULL:
		if (context)
			(*context)->handle = NULL;

		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

/**
 * aead_update_save_out_data() - Save intermediate output data
 * @subtest: Subtest data
 * @aead_args: SMW AEAD update arguments
 * @ctx_id: Local context ID
 *
 * If 'save_output' JSON parameter is set to 1, output data from a AEAD update
 * operation is saved in the AEAD output data linked list.
 *
 * Return:
 * PASSED		- Success
 * -BAD_PARAM_TYPE	- JSON parameter incorrectly set
 * Error code from util_aead_add_output_data
 */
static int aead_update_save_out_data(struct subtest_data *subtest,
				     struct smw_aead_data_args *aead_args,
				     unsigned int ctx_id)
{
	int res = ERR_CODE(PASSED);
	int save_flag = 0;

	res = util_read_json_type(&save_flag, SAVE_OUT_OBJ, t_int,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	if (save_flag && aead_args->output_length)
		res = util_aead_add_output_data(list_aeads(subtest), ctx_id,
						aead_args->output,
						aead_args->output_length);

	return res;
}

/**
 * aead_save_final_output_data() - Save final output data
 * @subtest: Subtest data
 * @aead_args: SMW AEAD data arguments
 * @ctx_id: Local context ID
 *
 * Output data from a AEAD final operation is saved in the AEAD
 * output data linked list.
 *
 * Return:
 * PASSED		- Success
 * -BAD_PARAM_TYPE	- JSON parameter incorrectly set
 * Error code from util_aead_add_output_data
 */
static int aead_save_final_output_data(struct subtest_data *subtest,
				       struct smw_aead_data_args *aead_args,
				       unsigned int ctx_id)
{
	int res = ERR_CODE(PASSED);

	if (aead_args->output_length)
		res = util_aead_add_output_data(list_aeads(subtest), ctx_id,
						aead_args->output,
						aead_args->output_length);

	return res;
}

/**
 * set_init_params() - Set AEAD initialization parameters
 * @subtest: Subtest data
 * @args: Pointer to SMW AEAD initialization API arguments
 * @key: Pointer to internal AEAD key structure
 * @key_buffer:  Pointer to keypair buffer
 *
 * Return:
 * PASSED	- Success
 * Error code from util_read_hex_buffer
 * Error code from key_read_descriptors
 */
static int set_init_params(struct subtest_data *subtest,
			   struct smw_aead_init_args *args,
			   struct keypair_ops *key,
			   struct smw_keypair_buffer *key_buffer)
{
	int res = ERR_CODE(PASSED);

	const char *key_name = NULL;

	if (subtest->subsystem) {
		if (!strcmp(subtest->subsystem, "DEFAULT"))
			args->subsystem_name = NULL;
		else
			args->subsystem_name = subtest->subsystem;
	}

	/* Get plaintext length, if any */
	res = util_read_json_type(&args->plaintext_length, PLAINTEXT_LEN_OBJ,
				  t_int, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD plaintext length");
		return res;
	}

	/* Get tag length - Mandatory */
	res = util_read_json_type(&args->tag_length, TAG_LEN_OBJ, t_int,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD tag length");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get the mode - Mandatory */
	res = util_read_json_type(&args->mode_name, MODE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD mode");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Read IV buffer - Mandatory */
	res = util_read_hex_buffer(&args->iv, &args->iv_length, subtest->params,
				   IV_OBJ);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD IV buffer");
		return res;
	}

	/* Get the operation type - Mandatory */
	res = util_read_json_type(&args->operation_name, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	args->key_desc = &key->desc;

	/* Get the Key name - Mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD Key name");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Initialize key descriptor */
	res = key_desc_init(key, key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), key, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_is_id_set(key))
		key_free_key(key);

	if (!key_is_id_set(key) && !is_api_test(subtest) &&
	    (!key_is_type_set(key) || !key_is_security_set(key) ||
	     !key_is_private_key_defined(key))) {
		DBG_PRINT_MISS_PARAM("Key description");
		res = ERR_CODE(MISSING_PARAMS);
	}

	return res;
}

/**
 * set_output_params() - Set AEAD output related parameters
 * @subtest: Subtest data
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @tag_len: Tag length
 * @args: Pointer to SMW AEAD data API arguments
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_output_params(struct subtest_data *subtest,
			     unsigned char **expected_output,
			     unsigned int *expected_out_len,
			     unsigned int tag_len,
			     struct smw_aead_data_args *args)
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
		/* Set a value large enough (input + tag length + AES block size):
		 * In case of final operation, if previous AEAD update
		 * operation was not a AEAD block size modulus, ensure that
		 * the final output buffer can contain the input data block +
		 * tag length + a AEAD block.
		 * Use the biggest AEAD block size which is AES block of 16
		 * bytes
		 */
		if (ADD_OVERFLOW(tag_len, AES_BLOCK_SIZE, &args->output_length))
			return ERR_CODE(BAD_ARGS);

		if (INC_OVERFLOW(args->output_length, args->input_length))
			return ERR_CODE(BAD_ARGS);

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
 * @subtest: Subtest data
 * @ctx_id: Pointer to context ID
 * @args: Pointer to SMW AEAD API arguments
 * @api_ctx: Pointer to API operation context structure
 * @cmd: AEAD command
 *
 * Return:
 * PASSED		- Success
 * -MISSING_PARAMS	- Context ID json parameter is missing
 * Error code from util_context_find_node
 */
static int set_op_context(struct subtest_data *subtest, unsigned int *ctx_id,
			  void *args, struct smw_op_context *api_ctx,
			  enum cmd cmd)
{
	int res = ERR_CODE(PASSED);

	struct smw_aead_aad_args *aad_args = NULL;
	struct smw_aead_data_args *data_args = NULL;

	if (cmd == UPDATE_ADD)
		aad_args = args;
	else if (cmd == UPDATE || cmd == FINAL)
		data_args = args;

	/* Context ID is a mandatory parameter except for API tests */
	res = util_read_json_type(ctx_id, CTX_ID_OBJ, t_int, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get operation context */
	if (*ctx_id != UINT_MAX) {
		if (cmd == UPDATE_ADD)
			res = util_context_find_node(list_op_ctxs(subtest),
						     *ctx_id,
						     &aad_args->context);
		else if ((cmd == UPDATE) || (cmd == FINAL))
			res = util_context_find_node(list_op_ctxs(subtest),
						     *ctx_id,
						     &data_args->context);

		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Failed to find context node");
			return res;
		}

	} else {
		/* API specific tests cases */
		if (cmd == UPDATE_ADD)
			aad_args->context = api_ctx;
		else if ((cmd == UPDATE) || (cmd == FINAL))
			data_args->context = api_ctx;
	}

	return ERR_CODE(PASSED);
}

int aead(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	struct smw_aead_args args = { 0 };
	struct smw_aead_args *aead_args = NULL;
	struct smw_aead_init_args *init = NULL;
	struct keypair_ops key = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	init = &args.init;
	aead_args = &args;

	args.init.version = subtest->version;
	args.data.version = subtest->version;

	res = set_init_params(subtest, init, &key, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read AAD buffer, if any */
	res = util_read_hex_buffer(&args.aad, &init->aad_length,
				   subtest->params, AAD_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read AAD buffer");
		goto end;
	}

	/* Read input buffer. Could not be set for API tests and  */
	res = util_read_hex_buffer(&args.data.input, &args.data.input_length,
				   subtest->params, INPUT_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	/* Allocate memory to output buffer */
	res = set_output_params(subtest, &expected_output, &expected_out_len,
				init->tag_length, &args.data);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args,
			      &aead_args->init.key_desc,
			      &aead_args->init.context, ONESHOT);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead(aead_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("Buffer too short, expected %u",
				  aead_args->data.output_length);

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

	if (args.aad)
		free(args.aad);

	key_free_key(&key);

	return res;
}

int aead_init(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	int ctx_id = -1;
	struct smw_aead_init_args args = { 0 };
	struct smw_aead_init_args *aead_args = &args;
	struct keypair_ops key = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct tbuffer aad = { 0 };

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

	res = set_init_params(subtest, aead_args, &key, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Get AAD length if any */
	res = util_read_json_type(&aad, AAD_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD AAD length");
		return res;
	}

	aead_args->aad_length = aad.length;

	args.context = malloc(sizeof(*args.context));
	if (!args.context) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args,
			      &aead_args->key_desc, &aead_args->context, INIT);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_init(aead_args);
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

	if (aad.data)
		free(aad.data);

	if (args.iv)
		free(args.iv);

	key_free_key(&key);

	return res;
}

int aead_update_aad(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int ctx_id = UINT_MAX;
	struct smw_aead_aad_args args = { 0 };
	struct smw_aead_aad_args *aead_args = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = set_op_context(subtest, &ctx_id, aead_args, &api_ctx, UPDATE_ADD);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read AAD buffer */
	res = util_read_hex_buffer(&args.aad, &args.aad_length, subtest->params,
				   AAD_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read AEAD buffer");
		goto end;
	}

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args, NULL, NULL,
			      UPDATE_ADD);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_update_add(aead_args);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

end:
	if (args.aad)
		free(args.aad);

	return res;
}

int aead_update(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	struct smw_aead_data_args args = { 0 };
	struct smw_aead_data_args *aead_args = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = set_op_context(subtest, &ctx_id, aead_args, &api_ctx, UPDATE);
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

	res = set_output_params(subtest, &expected_output, &expected_out_len, 0,
				aead_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args, NULL,
			      &aead_args->context, UPDATE);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_update(aead_args);

	/*
	 * Save output data if operation success.
	 * Output data is checked at final step
	 */
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);
	else
		res = aead_update_save_out_data(subtest, aead_args, ctx_id);

end:
	if (args.input)
		free(args.input);

	if (args.output)
		free(args.output);

	if (expected_output)
		free(expected_output);

	return res;
}

int aead_final(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int ctx_id = UINT_MAX;
	unsigned int expected_out_len = 0;
	unsigned int tag_len = 0;
	unsigned char *expected_output = NULL;
	struct smw_aead_final_args args = { 0 };
	struct smw_aead_final_args *aead_args = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.data.version = subtest->version;

	res = set_op_context(subtest, &ctx_id, &aead_args->data, &api_ctx,
			     FINAL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get the operation type - Mandatory */
	res = util_read_json_type(&aead_args->operation_name, OP_TYPE_OBJ,
				  t_string, subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Read input if any */
	res = util_read_hex_buffer(&args.data.input, &args.data.input_length,
				   subtest->params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	/* Get tag length */
	res = util_read_json_type(&aead_args->tag_length, TAG_LEN_OBJ, t_int,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD tag length");
		goto end;
	}

	/**
	 * In case of encryption operation, output = ciphertext + tag
	 * In case of encryption operation, output = decrypted plaintext
	 */
	if (!strcmp(aead_args->operation_name, "ENCRYPT"))
		tag_len = aead_args->tag_length;
	else
		tag_len = 0;

	res = set_output_params(subtest, &expected_output, &expected_out_len,
				tag_len, &aead_args->data);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args, NULL,
			      &aead_args->data.context, FINAL);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_final(aead_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (expected_output) {
		res = aead_save_final_output_data(subtest, &aead_args->data,
						  ctx_id);
		if (res != ERR_CODE(PASSED))
			goto end;

		res = util_aead_cmp_output_data(list_aeads(subtest), ctx_id,
						expected_output,
						expected_out_len);
	}

end:
	if (args.data.input)
		free(args.data.input);

	if (args.data.output)
		free(args.data.output);

	if (expected_output)
		free(expected_output);

	return res;
}
