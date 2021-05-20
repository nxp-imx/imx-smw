// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_context.h"
#include "util_cipher.h"
#include "types.h"
#include "json_types.h"
#include "keymgr.h"
#include "cipher.h"
#include "smw_keymgr.h"
#include "smw_crypto.h"
#include "smw_status.h"

/*
 * This identifier is used for test error tests.
 * It represents the following key:
 *  - Generated/Imported by subsystem ID 0
 *  - Type is AES
 *  - Parity is Private
 *  - Security size is 192
 *  - Subsystem Key ID is 1
 */
#define FAKE_KEY_AES_192_0_ID INT64_C(0x007000C000000001)

/*
 * This identifier is used for test error tests.
 * It represents the following key:
 *  - Generated/Imported by subsystem ID 0
 *  - Type is DES
 *  - Parity is Private
 *  - Security size is 56
 *  - Subsystem Key ID is 2
 */
#define FAKE_KEY_DES_56_0_ID INT64_C(0x0090003800000002)

/*
 * This identifier is used for test error tests.
 * It represents the following key:
 *  - Generated/Imported by subsystem ID 1
 *  - Type is AES
 *  - Parity is Private
 *  - Security size is 192
 *  - Subsystem Key ID is 1
 */
#define FAKE_KEY_AES_192_1_ID INT64_C(0x107000C000000001)

#define ONESHOT 0
#define INIT	1
#define UPDATE	2
#define FINAL	3

/*
 * Linked list containing cipher output data. It's used to be able to check the
 * result of a multi-part operation
 */
static struct cipher_output_list *cipher_out_data;

/**
 * struct cipher_keys - Group of structures representing keys
 * @nb_keys: Number of keys
 * @key_identifiers: Pointer to key identifiers linked list
 * @keys_id: Pointer to an array of local key ids
 * @keys_test: Pointer to an array of test keypair structures
 * @keys_desc: Pointer to an array of SMW key descriptor pointers
 * @keys_buffer: Pointer to an array of key buffer
 */
struct cipher_keys {
	unsigned int nb_keys;
	struct key_identifier_list *key_identifiers;
	int *keys_id;
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
static int cipher_bad_params(json_object *params,
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

	case CIPHER_NO_NB_KEYS:
		(*init)->nb_keys = 0;
		break;

	case KEY_DESC_ID_SET:
		(*init)->keys_desc[0]->id = FAKE_KEY_AES_192_1_ID;
		break;

	case CIPHER_NO_KEYS:
		(*init)->keys_desc[0]->id = 0;
		(*init)->keys_desc[0]->buffer = NULL;
		break;

	case CIPHER_DIFF_SUBSYSTEM:
		(*init)->keys_desc[0]->id = FAKE_KEY_AES_192_0_ID;
		(*init)->keys_desc[0]->buffer = NULL;
		(*init)->keys_desc[0]->security_size = 0;
		(*init)->keys_desc[1]->id = FAKE_KEY_AES_192_1_ID;
		(*init)->keys_desc[1]->buffer = NULL;
		(*init)->keys_desc[1]->security_size = 0;
		break;

	case CIPHER_DIFF_KEY_TYPE:
		(*init)->keys_desc[0]->id = FAKE_KEY_AES_192_0_ID;
		(*init)->keys_desc[0]->buffer = NULL;
		(*init)->keys_desc[0]->security_size = 0;
		(*init)->keys_desc[1]->id = FAKE_KEY_DES_56_0_ID;
		(*init)->keys_desc[1]->buffer = NULL;
		(*init)->keys_desc[1]->security_size = 0;
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
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

/**
 * get_cipher_config() - Get cipher operation configuration
 * @params: JSON Cipher parameters
 * @mode: Pointer to mode
 * @op_type: Pointer to operation type
 * @is_api_test: API test flag
 *
 * Configuration parameters could not be set for API tests only.
 *
 * Return:
 * PASSED		- Success
 * -MISSING_PARAMS	- Missing mandatory parameters in @params.
 */
static int get_cipher_config(json_object *params, const char **mode,
			     const char **op_type, int is_api_test)
{
	json_object *mode_obj;
	json_object *op_type_obj;

	if (json_object_object_get_ex(params, MODE_OBJ, &mode_obj)) {
		*mode = json_object_get_string(mode_obj);
	} else if (!is_api_test) {
		DBG_PRINT_MISS_PARAM(__func__, "Cipher mode");
		return ERR_CODE(MISSING_PARAMS);
	}

	if (json_object_object_get_ex(params, OP_TYPE_OBJ, &op_type_obj)) {
		*op_type = json_object_get_string(op_type_obj);
	} else if (!is_api_test) {
		DBG_PRINT_MISS_PARAM(__func__, "Cipher operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	return ERR_CODE(PASSED);
}

/**
 * allocate_keys() - Allocate all fields present in cipher keys structure
 * @params: JSON Cipher parameters
 * @keys: Pointer to structure to update
 * @nb_keys: Pointer to number of keys variable to update
 *
 * This function gets the number of keys set in the test definition file and
 * allocate dedicated key structures.
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failure
 */
static int allocate_keys(json_object *params, struct cipher_keys *keys,
			 unsigned int *nb_keys)
{
	int *keys_id = NULL;
	struct keypair_ops *keys_test = NULL;
	struct smw_key_descriptor **keys_desc = NULL;
	struct smw_keypair_buffer *keys_buffer = NULL;
	json_object *nb_keys_obj;

	/* Get number of keys parameter. Default is 1 */
	if (json_object_object_get_ex(params, NB_KEYS_OBJ, &nb_keys_obj))
		keys->nb_keys = json_object_get_int(nb_keys_obj);
	else
		keys->nb_keys = 1;

	/* Allocate keypair ops array */
	keys_test = malloc(keys->nb_keys * sizeof(struct keypair_ops));
	if (!keys_test)
		goto err;

	/* Allocate keys descriptor array */
	keys_desc = malloc(keys->nb_keys * sizeof(struct smw_key_descriptor *));
	if (!keys_desc)
		goto err;

	/* Allocate keys buffer array */
	keys_buffer = malloc(keys->nb_keys * sizeof(*keys_buffer));
	if (!keys_buffer)
		goto err;

	/* Allocate keys id array */
	keys_id = malloc(keys->nb_keys * sizeof(int));
	if (!keys_id)
		goto err;

	keys->keys_test = keys_test;
	keys->keys_desc = keys_desc;
	keys->keys_buffer = keys_buffer;
	keys->keys_id = keys_id;

	*nb_keys = keys->nb_keys;

	return ERR_CODE(PASSED);

err:
	if (keys_test)
		free(keys_test);

	if (keys_desc)
		free(keys_desc);

	if (keys_buffer)
		free(keys_buffer);

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

	if (keys->keys_id)
		free(keys->keys_id);

	for (i = 0; i < keys->nb_keys; i++)
		util_key_free_key(&keys->keys_test[i]);

	if (keys->keys_buffer)
		free(keys->keys_buffer);

	if (keys->keys_test)
		free(keys->keys_test);
}

/**
 * set_keys() - Set cipher keys structure
 * @params: JSON Cipher parameters
 * @keys: Pointer to structure to update
 * @nb_keys: Pointer to number of keys variable to update
 * @out_keys_desc: Pointer to output SMW key descriptors pointer array to update
 * @is_api_test: API test flag
 *
 * This function reads the keys description present in the test definition file
 * and set the keys structure.
 *
 * Return:
 * PASSED		- Success
 * -BAD_RESULT		- SMW API function failed
 * -MISSING_PARAMS	- Mandatory parameters are missing
 * Error code from allocate_keys
 * Error code from util_key_desc_init
 * Error code from util_key_read_descriptor
 * Error code from util_key_find_key_node
 */
static int set_keys(json_object *params, struct cipher_keys *keys,
		    unsigned int *nb_keys,
		    struct smw_key_descriptor ***out_keys_desc, int is_api_test)
{
	int status;
	int res = ERR_CODE(BAD_ARGS);
	unsigned int i;
	struct smw_key_descriptor *desc;
	struct keypair_ops *key_test;

	res = allocate_keys(params, keys, nb_keys);
	if (res != ERR_CODE(PASSED))
		return res;

	for (i = 0; i < keys->nb_keys; i++) {
		key_test = &keys->keys_test[i];
		keys->keys_id[i] = INT_MAX;

		/* Initialize key descriptor */
		res = util_key_desc_init(key_test, &keys->keys_buffer[i], NULL);
		if (res != ERR_CODE(PASSED))
			return res;

		/* Read the json-c key description */
		res = util_key_read_descriptor(key_test, &keys->keys_id[i], i,
					       params);
		if (res != ERR_CODE(PASSED))
			return res;

		if (keys->keys_id[i] != INT_MAX) {
			util_key_free_key(key_test);
			util_key_desc_init(key_test, NULL, NULL);

			res = util_key_find_key_node(keys->key_identifiers,
						     keys->keys_id[i],
						     key_test);
			if (res != ERR_CODE(PASSED))
				return res;

			/*
			 * If Security size not set,
			 * get it from the SMW key identifier
			 */
			if (!util_key_is_security_set(key_test)) {
				desc = &key_test->desc;
				status = smw_get_security_size(desc);
				if (status != SMW_STATUS_OK) {
					res = ERR_CODE(BAD_RESULT);
					return res;
				}
			}
		} else if (!is_api_test &&
			   (!util_key_is_type_set(key_test) ||
			    !util_key_is_security_set(key_test) ||
			    !util_key_is_private_key_defined(key_test))) {
			DBG_PRINT_MISS_PARAM(__func__, "Key description");
			res = ERR_CODE(MISSING_PARAMS);
			return res;
		}

		keys->keys_desc[i] = &key_test->desc;
	}

	*out_keys_desc = keys->keys_desc;

	return ERR_CODE(PASSED);
}

/**
 * cipher_update_save_out_data() - Save intermediate output data
 * @params: JSON Cipher parameters
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
static int cipher_update_save_out_data(json_object *params,
				       struct smw_cipher_data_args *cipher_args,
				       int ctx_id)
{
	json_object *save_output_obj;

	if (!json_object_object_get_ex(params, SAVE_OUT_OBJ, &save_output_obj))
		return ERR_CODE(PASSED);

	if (json_object_get_type(save_output_obj) != json_type_int) {
		DBG_PRINT_BAD_PARAM(__func__, SAVE_OUT_OBJ);
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	if (json_object_get_int(save_output_obj) != 1) {
		DBG_PRINT("Save output parameter is ignored");
		return ERR_CODE(PASSED);
	}

	return util_cipher_add_out_data(&cipher_out_data, ctx_id,
					cipher_args->output,
					cipher_args->output_length);
}

/**
 * set_init_params() - Set cipher initialization parameters
 * @params: JSON Cipher parameters
 * @common_params: Common commands parameters
 * @args: Pointer to SMW cipher initialization API arguments
 * @keys: Pointer to internal cipher keys structure
 *
 * Return:
 * PASSED	- Success
 * Error code from get_cipher_config
 * Error code from util_read_hex_buffer
 * Error code from set_keys
 */
static int set_init_params(json_object *params,
			   struct common_parameters *common_params,
			   struct smw_cipher_init_args *args,
			   struct cipher_keys *keys)
{
	int res;

	if (common_params->subsystem) {
		if (!strcmp(common_params->subsystem, "DEFAULT"))
			args->subsystem_name = NULL;
		else
			args->subsystem_name = common_params->subsystem;
	}

	/* Get mode and operation type */
	res = get_cipher_config(params, &args->mode_name, &args->operation_name,
				common_params->is_api_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read IV buffer if any */
	res = util_read_hex_buffer(&args->iv, &args->iv_length, params, IV_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read IV buffer");
		return res;
	}

	/* Set key descriptors */
	res = set_keys(params, keys, &args->nb_keys, &args->keys_desc,
		       common_params->is_api_test);

	return res;
}

/**
 * set_output_params() - Set cipher output related parameters
 * @params: JSON Cipher parameters
 * @common_params: Common commands parameters
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @args: Pointer to SMW cipher data API arguments
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_output_params(json_object *params,
			     struct common_parameters *common_params,
			     unsigned char **expected_output,
			     unsigned int *expected_out_len,
			     struct smw_cipher_data_args *args)
{
	int res;

	/* Read expected output buffer */
	res = util_read_hex_buffer(expected_output, expected_out_len, params,
				   OUTPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read output buffer");
		return res;
	}

	/* Output length is not set by definition file */
	if (res == ERR_CODE(MISSING_PARAMS) ||
	    (common_params->is_api_test && !*expected_out_len &&
	     *expected_output)) {
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
		if (common_params->is_api_test && !*expected_out_len &&
		    *expected_output)
			args->output_length = 0;
	}

	return ERR_CODE(PASSED);
}

/**
 * set_op_context() - Set operation context
 * @params: JSON Cipher parameters
 * @is_api_test: API test flag
 * @pctx: Pointer to context linked list
 * @ctx_id: Pointer to context ID
 * @args: Pointer to SMW cipher data API arguments
 * @api_ctx: Pointer to API operation context structure
 *
 * Return:
 * PASSED		- Success
 * -MISSING_PARAMS	- Context ID json parameter is missing
 * Error code from util_context_find_node
 */
static int set_op_context(json_object *params, int is_api_test,
			  struct context_list *ctx, int *ctx_id,
			  struct smw_cipher_data_args *args,
			  struct smw_op_context *api_ctx)
{
	int res;
	json_object *ctx_id_obj;

	/* Context ID is a mandatory parameter except for API tests */
	if (json_object_object_get_ex(params, CTX_ID_OBJ, &ctx_id_obj)) {
		*ctx_id = json_object_get_int(ctx_id_obj);
	} else if (!is_api_test) {
		DBG_PRINT_MISS_PARAM(__func__, "Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Get operation context */
	if (*ctx_id != -1) {
		res = util_context_find_node(ctx, *ctx_id, &args->context);
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

int cipher(json_object *params, struct common_parameters *common_params,
	   struct key_identifier_list *key_identifiers, int *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int expected_out_len;
	unsigned char *expected_output = NULL;
	struct smw_cipher_args args = { 0 };
	struct smw_cipher_args *cipher_args = &args;
	struct smw_cipher_init_args *init = &args.init;
	struct cipher_keys keys = { 0 };

	if (!params || !common_params || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	keys.key_identifiers = key_identifiers;

	args.init.version = common_params->version;
	args.data.version = common_params->version;

	res = set_init_params(params, common_params, init, &keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read input buffer. Could not be set for API tests only */
	res = util_read_hex_buffer(&args.data.input, &args.data.input_length,
				   params, INPUT_OBJ);
	if ((!common_params->is_api_test && res != ERR_CODE(PASSED)) ||
	    (common_params->is_api_test && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_output_params(params, common_params, &expected_output,
				&expected_out_len, &args.data);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(params, &cipher_args, &init, NULL, ONESHOT);
	if (res != ERR_CODE(PASSED))
		goto end;

	*ret_status = smw_cipher(cipher_args);
	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto end;
	}

	/* Optional output comparison */
	if (*ret_status == SMW_STATUS_OK && args.data.output && expected_output)
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

int cipher_init(json_object *params, struct common_parameters *common_params,
		struct key_identifier_list *key_identifiers,
		struct context_list **ctx, int *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int ctx_id = -1;
	struct smw_cipher_init_args args = { 0 };
	struct smw_cipher_init_args *cipher_args = &args;
	struct smw_op_context *context;
	struct cipher_keys keys = { 0 };
	json_object *ctx_id_obj;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	/* Context ID is a mandatory parameter except for API tests */
	if (json_object_object_get_ex(params, CTX_ID_OBJ, &ctx_id_obj)) {
		ctx_id = json_object_get_int(ctx_id_obj);
	} else if (!common_params->is_api_test) {
		DBG_PRINT_MISS_PARAM(__func__, "Context ID");
		return ERR_CODE(MISSING_PARAMS);
	}

	keys.key_identifiers = key_identifiers;

	args.version = common_params->version;

	res = set_init_params(params, common_params, cipher_args, &keys);
	if (res != ERR_CODE(PASSED))
		goto end;

	context = malloc(sizeof(*context));
	if (!context) {
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto end;
	}

	args.context = context;

	/* Specific test cases */
	res = cipher_bad_params(params, NULL, &cipher_args, NULL, INIT);
	if (res != ERR_CODE(PASSED)) {
		free(context);
		goto end;
	}

	*ret_status = smw_cipher_init(cipher_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		res = ERR_CODE(BAD_RESULT);

	/*
	 * Add context in linked list if initialization succeed and test isn't
	 * an API test
	 */
	if (res == ERR_CODE(PASSED) && *ret_status == SMW_STATUS_OK &&
	    !common_params->is_api_test) {
		res = util_context_add_node(ctx, ctx_id, context);
		if (res == ERR_CODE(PASSED))
			goto end;

		DBG_PRINT("Failed to add context node");
	}

	free(context);

end:
	if (args.iv)
		free(args.iv);

	free_keys(&keys);

	return res;
}

int cipher_update(json_object *params, struct common_parameters *common_params,
		  struct context_list *ctx, int *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int ctx_id = -1;
	unsigned int expected_out_len;
	unsigned char *expected_output = NULL;
	struct smw_cipher_data_args args = { 0 };
	struct smw_cipher_data_args *cipher_args = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	args.version = common_params->version;

	res = set_op_context(params, common_params->is_api_test, ctx, &ctx_id,
			     cipher_args, &api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input buffer. Could not be set for API tests only */
	res = util_read_hex_buffer(&args.input, &args.input_length, params,
				   INPUT_OBJ);
	if ((!common_params->is_api_test && res != ERR_CODE(PASSED)) ||
	    (common_params->is_api_test && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_output_params(params, common_params, &expected_output,
				&expected_out_len, cipher_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(params, NULL, NULL, &cipher_args, UPDATE);
	if (res != ERR_CODE(PASSED))
		goto end;

	*ret_status = smw_cipher_update(cipher_args);
	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto end;
	}

	/* Save output data if result is checked at final step */
	if (*ret_status == SMW_STATUS_OK)
		res = cipher_update_save_out_data(params, cipher_args, ctx_id);

end:
	if (args.input)
		free(args.input);

	if (args.output)
		free(args.output);

	if (expected_output)
		free(expected_output);

	return res;
}

int cipher_final(json_object *params, struct common_parameters *common_params,
		 struct context_list *ctx, int *ret_status)
{
	int res = ERR_CODE(BAD_ARGS);
	int ctx_id = -1;
	unsigned int expected_out_len;
	unsigned char *expected_output = NULL;
	struct smw_cipher_data_args args = { 0 };
	struct smw_cipher_data_args *cipher_args = &args;
	struct smw_op_context api_ctx = { .handle = &api_ctx };

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	args.version = common_params->version;

	res = set_op_context(params, common_params->is_api_test, ctx, &ctx_id,
			     cipher_args, &api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read input if any */
	res = util_read_hex_buffer(&args.input, &args.input_length, params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_output_params(params, common_params, &expected_output,
				&expected_out_len, cipher_args);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = cipher_bad_params(params, NULL, NULL, &cipher_args, FINAL);
	if (res != ERR_CODE(PASSED))
		goto end;

	*ret_status = smw_cipher_final(cipher_args);
	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto end;
	}

	if (*ret_status == SMW_STATUS_OK && expected_output) {
		res = util_cipher_add_out_data(&cipher_out_data, ctx_id,
					       cipher_args->output,
					       cipher_args->output_length);
		if (res != ERR_CODE(PASSED))
			goto end;

		res = compare_output_data(cipher_out_data, ctx_id,
					  expected_output, expected_out_len);
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

void cipher_clear_out_data_list(void)
{
	util_cipher_clear_out_data_list(cipher_out_data);
}
