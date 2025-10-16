// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <string.h>

#include <json.h>

#include <smw/names.h>
#include <smw_keymgr.h>
#include <smw/crypto/aead.h>

#include "util.h"
#include "util_aead.h"
#include "util_context.h"

#include "key.h"
#include "aead.h"

#define MAX_IV_LEN 12

#define AEAD_MODE(_name)                                                       \
	{                                                                      \
		.name = SMW_AEAD_MODE_NAME_##_name, .string = #_name           \
	}

static struct {
	smw_aead_mode_t name;
	const char *string;
} aead_mode_names[] = { AEAD_MODE(CCM), AEAD_MODE(CHACHA20_POLY1305),
			AEAD_MODE(GCM) };

#define AEAD_OP_TYPE(_name)                                                    \
	{                                                                      \
		.name = SMW_AEAD_OP_TYPE_NAME_##_name, .string = #_name        \
	}

static struct {
	smw_aead_op_type_t name;
	const char *string;
} aead_op_type_names[] = { AEAD_OP_TYPE(ENCRYPT), AEAD_OP_TYPE(DECRYPT) };

smw_aead_mode_t aead_get_mode_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_AEAD_MODE_NAME_NONE;

	for (; i < ARRAY_SIZE(aead_mode_names); i++) {
		if (!strcmp(aead_mode_names[i].string, string))
			return aead_mode_names[i].name;
	}

	return SMW_AEAD_MODE_NAME_NB + 1;
}

smw_aead_op_type_t aead_get_op_type_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_AEAD_OP_TYPE_NAME_NONE;

	for (; i < ARRAY_SIZE(aead_op_type_names); i++) {
		if (!strcmp(aead_op_type_names[i].string, string))
			return aead_op_type_names[i].name;
	}

	return SMW_AEAD_OP_TYPE_NAME_NB + 1;
}

/**
 * aead_bad_params() - Set AEAD bad parameters
 * @params: JSON AEAD parameters
 * @arg: SMW AEAD arguments
 * @key: Key descriptor
 * @context: SMW cryptographic operation context
 *
 * Return:
 * PASSED           - Success.
 * -BAD_PARAM_TYPE  - Test error is not suuported.
 * -BAD_ARGS        - One of the argument is bad.
 */
static int aead_bad_params(struct json_object *params, void **arg,
			   struct smw_key_descriptor **key,
			   struct smw_op_context **context)
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
		if (context)
			*context = NULL;

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
 * If 'save_output' JSON parameter is set to true, output data from a AEAD update
 * operation is saved in the AEAD output data linked list.
 *
 * Return:
 * PASSED           - Success
 * -BAD_PARAM_TYPE  - JSON parameter incorrectly set
 * Error code from autil_read_json_type
 * Error code from util_aead_add_output_data
 */
static int aead_update_save_out_data(struct subtest_data *subtest,
				     struct smw_aead_data_args *aead_args,
				     unsigned int ctx_id)
{
	int res = ERR_CODE(PASSED);
	bool save_flag = false;

	res = util_read_json_type(&save_flag, SAVE_OUT_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	if (save_flag && aead_args->output_length)
		res = util_aead_add_output_data(list_aeads(subtest), ctx_id,
						aead_args->output,
						aead_args->output_length, NULL,
						0, NULL, 0);

	return res;
}

/**
 * aead_save_final_output_data() - Save final output data
 * @subtest: Subtest data
 * @aead_args: SMW AEAD data arguments
 * @ctx_id: Local context ID
 *
 * Output data from a AEAD final operation is saved in the AEAD output data
 * linked list.
 *
 * Return:
 * PASSED   - Success
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
						aead_args->output_length, NULL,
						0, NULL, 0);

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
 * PASSED   - Success
 * Error code from util_read_hex_buffer
 * Error code from key_read_descriptors
 * Error code from util_read_json_type
 */
static int set_init_params(struct subtest_data *subtest,
			   struct smw_aead_init_args *args,
			   struct keypair_ops *key,
			   struct smw_keypair_buffer *key_buffer)
{
	int res = ERR_CODE(PASSED);

	const char *mode_string = NULL;
	const char *op_type_string = NULL;

	const char *key_name = NULL;

	args->subsystem_name = subtest->subsystem;

	/* Get plaintext length, if any */
	res = util_read_json_type(&args->plaintext_length, PLAINTEXT_LEN_OBJ,
				  t_uint, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD plaintext length");
		return res;
	}

	/* Get the mode - Mandatory */
	res = util_read_json_type(&mode_string, MODE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD mode");
		return ERR_CODE(MISSING_PARAMS);
	}

	args->mode_name = aead_get_mode_name(mode_string);

	/* Get the operation type - Mandatory */
	res = util_read_json_type(&op_type_string, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	args->op_type_name = aead_get_op_type_name(op_type_string);

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
 * set_tag_params() - Set AEAD tag parameters
 * @subtest: Subtest data
 * @expected_tag: Pointer to expected tag buffer
 * @expected_tag_len: Pointer to expected tag buffer length
 * @args: Pointer to SMW AEAD final API arguments
 * @encrypt_op: True if the operation is encryption
 * @tag_field_set: True if the tag is set in the dedicated tag field
 *
 * Set AEAD tag parameters for AEAD encryption and decryption operation.
 *
 * Return:
 * PASSED                   - Success
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_tag_params(struct subtest_data *subtest,
			  unsigned char **expected_tag,
			  unsigned int *expected_tag_len,
			  struct smw_aead_final_args *args, bool encrypt_op,
			  bool tag_field_set)
{
	int res = ERR_CODE(PASSED);

	/* Read expected tag buffer */
	res = util_read_hex_buffer(expected_tag, expected_tag_len,
				   subtest->params, TAG_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read tag buffer");
		return res;
	}

	if (encrypt_op) {
		if (*expected_tag) {
			args->tag_length = *expected_tag_len;

			if (tag_field_set) {
				args->tag = malloc(args->tag_length);
				if (!args->tag)
					return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			}

		} else if (*expected_tag_len && tag_field_set) {
			args->tag_length = *expected_tag_len;
			args->tag = malloc(args->tag_length);
			if (!args->tag)
				return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		} else if (*expected_tag_len) {
			args->tag_length = *expected_tag_len;
			args->tag = NULL;
		} else {
			return res;
		}
	} else {
		if (*expected_tag) {
			args->tag_length = *expected_tag_len;
			args->tag = *expected_tag;
		} else if (*expected_tag_len) {
			args->tag_length = *expected_tag_len;
		} else {
			return res;
		}
	}

	return ERR_CODE(PASSED);
}

/**
 * set_output_length() - Set output buffer length
 * @input_len: Pointer to input buffer length
 * @tag_len: Pointer to tag length
 * @output_len: Pointer to output buffer length
 * @encrypt_op: True if the operation is encryption
 * @tag_field_set: True if the tag is set in the dedicated tag field
 *
 * Set output buffer length based on input buffer length and tag length.
 *
 * Return:
 * PASSED           - Success
 * -BAD_ARGS        - One of the argument is bad.
 */
static int set_output_length(unsigned int *input_len, unsigned int *tag_len,
			     unsigned int *output_len, bool encrypt_op,
			     bool tag_field_set)
{
	*output_len = 0;

	if (SET_OVERFLOW(*input_len, *output_len))
		return ERR_CODE(BAD_ARGS);

	if (!tag_field_set) {
		if (encrypt_op) {
			if (INC_OVERFLOW(*output_len, *tag_len))
				return ERR_CODE(BAD_ARGS);

		} else {
			if (DEC_OVERFLOW(*output_len, *tag_len))
				return ERR_CODE(BAD_ARGS);
		}
	}

	return ERR_CODE(PASSED);
}

/**
 * set_output_params() - Set AEAD output related parameters
 * @subtest: Subtest data
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @tag_len: Tag length
 * @args: Pointer to SMW AEAD data API arguments
 * @encrypt_op: True if the operation is encryption
 * @tag_field_set: True if the tag is set in the dedicated tag field
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
			     unsigned int tag_len,
			     struct smw_aead_data_args *args, bool encrypt_op,
			     bool dedicated_tag_field)
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
		res = set_output_length(&args->input_length, &tag_len,
					&args->output_length, encrypt_op,
					dedicated_tag_field);
		if (res != ERR_CODE(PASSED))
			return res;

	} else {
		args->output_length = *expected_out_len;
	}

	/* If length is set to 0 by definition file output pointer is NULL */
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

/**
 * set_update_output_params() - Set output parameters for AEAD update opertion
 * @subtest: Subtest data
 * @expected_output: Pointer to expected output buffer
 * @expected_out_len: Pointer to expected output buffer length
 * @args: Pointer to SMW AEAD data API arguments
 *
 * Set output parameters (expected output buffer, expected output buffer length,
 * out buffer, output buffer length) for AEAD update operation.
 *
 * Return:
 * PASSED                   - Success
 * -BAD_ARGS                - One of the argument is bad
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int set_update_output_params(struct subtest_data *subtest,
				    unsigned char **expected_output,
				    unsigned int *expected_out_len,
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
		if (SET_OVERFLOW(args->input_length, args->output_length))
			return ERR_CODE(BAD_ARGS);

	} else {
		args->output_length = *expected_out_len;
	}

	/* If length is set to 0 by definition file output pointer is NULL */
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

/**
 * set_encrypt_iv_params() - Set AEAD IV parameters for encryption operation
 * @subtest: Subtest data
 * @output_iv: Double pointer to output IV buffer
 * @output_iv_len: Pointer to output IV buffer length
 * @iv: Pointer to user supplied IV buffer
 * @iv_len: Double pointer to user supplied IV buffer length
 *
 * This sets AEAD IV parameters (iv, iv_length, output_iv and output_iv_length)
 * for encryption operation.
 *
 * Return:
 * PASSED                   - Success
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed
 * Error code from util_read_hex_buffer
 */
static int
set_encrypt_iv_params(struct subtest_data *subtest, unsigned char **output_iv,
		      unsigned int *output_iv_len, unsigned char **user_iv,
		      unsigned int *user_iv_len, unsigned int *iv_len)
{
	int res = ERR_CODE(PASSED);

	*iv_len = 0;

	res = util_read_hex_buffer(user_iv, user_iv_len, subtest->params,
				   IV_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read AEAD IV");
		return res;
	}

	util_read_json_type(iv_len, IV_LEN_OBJ, t_int, subtest->params);
	if (*iv_len == 0)
		*iv_len = MAX_IV_LEN;

	if (*user_iv_len < MAX_IV_LEN)
		*output_iv_len = MAX_IV_LEN;
	else
		*output_iv_len = *user_iv_len;

	*output_iv = calloc(1, *output_iv_len * (sizeof(**output_iv)));
	if (!*output_iv)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	return res;
}

/**
 * compare_tag() - Compare tag received from subsystem with expected tag
 * @args: Pointer to SMW AEAD final API arguments
 * @expected_tag: Pointer to expected output buffer
 * @expected_tag_len: Pointer to expected output buffer length
 * @tag_field_set: True if the tag is set in the dedicated tag field
 *
 * For encryption operation, compare tag received from the subsystem
 * with expected tag, if the expected tag is set in the JSON file.
 *
 * Return:
 * PASSED           - Success
 * -BAD_ARGS        - One of the argument is bad
 * Error code from util_compare_buffers
 */
static int compare_tag(struct smw_aead_final_args *args,
		       unsigned char *expected_tag,
		       unsigned int expected_tag_len, bool tag_field_set)
{
	int res = ERR_CODE(PASSED);

	unsigned int index = 0;

	if (!expected_tag)
		return res;

	if (tag_field_set) {
		res = util_compare_buffers(args->tag, args->tag_length,
					   expected_tag, expected_tag_len);
	} else {
		if (!args->data->output || !args->data->output_length ||
		    args->tag_length > args->data->output_length)
			res = ERR_CODE(BAD_ARGS);
		else if (!SUB_OVERFLOW(args->data->output_length,
				       args->tag_length, &index))
			res = util_compare_buffers(&args->data->output[index],
						   args->tag_length,
						   expected_tag,
						   expected_tag_len);
		else
			res = ERR_CODE(BAD_ARGS);
	}

	return res;
}

/**
 * compare_output() - Compare output received with expected output
 * @args: Pointer to SMW AEAD final API arguments
 * @expected_output: Pointer to expected output buffer
 * @expected_output_len: Pointer to expected output buffer length
 *
 * Compare output with expected output, if the expected output buffer is set in
 * the JSON file.
 *
 * Return:
 * PASSED - Success
 * Error code from util_compare_buffers
 */
static int compare_output(struct smw_aead_final_args *args,
			  unsigned char *expected_output,
			  unsigned int expected_output_len)
{
	int res = ERR_CODE(PASSED);

	if (args->data->output && expected_output)
		res = util_compare_buffers(args->data->output,
					   args->data->output_length,
					   expected_output,
					   expected_output_len);

	return res;
}

/**
 * compare_output_and_tag() - Compare tag and output
 * @args: Pointer to SMW AEAD final API arguments
 * @expected_output: Pointer to expected output buffer
 * @expected_output_len: Pointer to expected output buffer length
 * @expected_tag: Pointer to expected tag buffer
 * @expected_tag_len: Pointer to expected tag buffer length
 * @tag_field_set: True if the tag is set in the dedicated tag field
 *
 * For encryption operation, compare tag received from the subsystem
 * with expected tag, if the expected tag is set in the JSON file.
 *
 * Return:
 * PASSED   - Success
 * Error code from util_compare_buffers
 */
static int compare_output_and_tag(struct smw_aead_final_args *args,
				  unsigned char *expected_output,
				  unsigned int expected_output_len,
				  unsigned char *expected_tag,
				  unsigned int expected_tag_len,
				  bool tag_field_set)
{
	int res = ERR_CODE(PASSED);

	res = compare_output(args, expected_output, expected_output_len);
	if (res == ERR_CODE(PASSED))
		res = compare_tag(args, expected_tag, expected_tag_len,
				  tag_field_set);

	return res;
}

static int set_final_output_iv_params(struct subtest_data *subtest,
				      unsigned char **output_iv,
				      unsigned int *output_iv_len)
{
	int res = ERR_CODE(PASSED);

	unsigned int iv_len = 0;

	res = util_read_json_type(&iv_len, IV_OBJ, t_uint, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD IV length");
		return res;
	}

	if (iv_len < MAX_IV_LEN)
		*output_iv_len = MAX_IV_LEN;
	else
		*output_iv_len = iv_len;

	*output_iv = calloc(1, *output_iv_len * (sizeof(**output_iv)));
	if (!*output_iv)
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

	return res;
}

/**
 * aead_encrypt() - Perform one-shot AEAD encryption operation
 * @subtest: Subtest data
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
static int aead_encrypt(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_aead_args args = { 0 };
	struct smw_aead_args *aead_args = NULL;
	struct smw_aead_init_args init = { 0 };
	struct smw_aead_aad_args aad = { 0 };
	struct smw_aead_final_args final = { 0 };
	struct smw_aead_data_args data = { 0 };
	struct keypair_ops key = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	unsigned int aead_id = UINT_MAX;
	bool tag_field_set = false;
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	unsigned int expected_tag_len = 0;
	unsigned char *expected_tag = NULL;

	args.init = &init;
	args.final = &final;
	args.final->data = &data;
	args.aad = &aad;
	aead_args = &args;

	args.init->version = subtest->version;
	args.final->version = subtest->version;
	args.final->data->version = subtest->version;
	args.aad->version = subtest->version;

	res = set_init_params(subtest, args.init, &key, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = set_encrypt_iv_params(subtest, &args.final->output_iv,
				    &args.final->output_iv_length,
				    &args.init->user_iv,
				    &args.init->user_iv_length,
				    &args.init->iv_length);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto end;

	/* Read AAD buffer, if any */
	res = util_read_hex_buffer(&args.aad->data, &args.aad->data_length,
				   subtest->params, AAD_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read AAD buffer");
		goto end;
	}

	res = util_read_json_type(&tag_field_set, TAG_FIELD_SET_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	/* Get 'aead_id' parameter, if any */
	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	if (aead_id != UINT_MAX) {
		res = util_aead_find_node(list_aead_output(subtest), aead_id,
					  &args.final->data->input,
					  &args.final->data->input_length,
					  &args.final->tag,
					  &args.final->tag_length,
					  &args.init->user_iv,
					  &args.init->user_iv_length,
					  tag_field_set);

		/* 'aead_id' must not be in the AEAD list */
		if (res == ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(AEAD_ID_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto end;
		}
	}

	/* Read input buffer */
	res = util_read_hex_buffer(&args.final->data->input,
				   &args.final->data->input_length,
				   subtest->params, INPUT_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	res = set_tag_params(subtest, &expected_tag, &expected_tag_len, &final,
			     true, tag_field_set);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS)))
		goto end;

	/* Allocate memory to output buffer */
	res = set_output_params(subtest, &expected_output, &expected_out_len,
				args.final->tag_length, args.final->data, true,
				tag_field_set);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args,
			      &args.init->key_desc, &args.init->context);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead(aead_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("Buffer too short, expected %u",
				  args.final->data->output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (aead_id != UINT_MAX) {
		/*
		 * Copy ciphertext, tag and output IV params to "aead_output" list,
		 * if aead_id is set.
		 */
		res = util_aead_add_output_data(list_aead_output(subtest),
						aead_id,
						args.final->data->output,
						args.final->data->output_length,
						args.final->tag,
						args.final->tag_length,
						args.final->output_iv,
						args.final->output_iv_length);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	res = compare_output_and_tag(args.final, expected_output,
				     expected_out_len, expected_tag,
				     expected_tag_len, tag_field_set);

end:

	if (args.init->user_iv)
		free(args.init->user_iv);

	if (args.final->output_iv)
		free(args.final->output_iv);

	if (args.aad->data)
		free(args.aad->data);

	if (args.final->data->input)
		free(args.final->data->input);

	if (args.final->data->output)
		free(args.final->data->output);

	if (args.final->tag)
		free(args.final->tag);

	if (expected_output)
		free(expected_output);

	if (expected_tag)
		free(expected_tag);

	key_free_key(&key);

	return res;
}

/**
 * aead_decrypt() - Perform one-shot AEAD decryption operation
 * @subtest: Subtest data
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
static int aead_decrypt(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_aead_args args = { 0 };
	struct smw_aead_args *aead_args = NULL;
	struct smw_aead_init_args init = { 0 };
	struct smw_aead_aad_args aad = { 0 };
	struct smw_aead_final_args final = { 0 };
	struct smw_aead_data_args data = { 0 };
	struct keypair_ops key = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };

	unsigned int aead_id = UINT_MAX;
	bool tag_field_set = false;
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	unsigned int input_len = 0;
	unsigned char *input = NULL;
	unsigned int tag_len = 0;
	unsigned char *tag = NULL;
	unsigned int iv_len = 0;
	unsigned char *iv = NULL;

	args.init = &init;
	args.final = &final;
	args.final->data = &data;
	args.aad = &aad;
	aead_args = &args;

	args.init->version = subtest->version;
	args.final->version = subtest->version;
	args.final->data->version = subtest->version;
	args.aad->version = subtest->version;

	res = set_init_params(subtest, args.init, &key, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read AAD buffer, if any */
	res = util_read_hex_buffer(&args.aad->data, &args.aad->data_length,
				   subtest->params, AAD_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read AAD buffer");
		goto end;
	}

	/* Read 'tag_field_set' parameter, if any */
	res = util_read_json_type(&tag_field_set, TAG_FIELD_SET_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	/* Read 'aead_id' parameter, if any */
	res = util_read_json_type(&aead_id, AEAD_ID_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto end;

	/*
	 * If aead_id is set, point input, tag and iv buffers to the respective
	 * members of the linked list node that were saved during the
	 * encryption operation.
	 */
	if (aead_id != UINT_MAX) {
		res = util_aead_find_node(list_aead_output(subtest), aead_id,
					  &args.final->data->input,
					  &args.final->data->input_length,
					  &args.final->tag,
					  &args.final->tag_length,
					  &args.init->user_iv,
					  &args.init->user_iv_length,
					  tag_field_set);

		/* 'aead_id' must be in the AEAD list */
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT_BAD_PARAM(AEAD_ID_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto end;
		}
	}

	/*
	 * If input data buffer is defined in the JSON, use this
	 * buffer in the decryption operation. Even if AEAD_ID is set, the input
	 * data buffer saved in the list will be not be utilized.
	 * The same applies to the iv buffer.
	 */
	res = util_read_decryption_input_buffer(subtest, &input, &input_len,
						aead_id, INPUT_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS)))
		goto end;

	if (input) {
		args.final->data->input = input;
		args.final->data->input_length = input_len;
	}

	/* Read iv buffer, if any  */
	res = util_read_decryption_input_buffer(subtest, &iv, &iv_len, aead_id,
						IV_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS)))
		goto end;

	if (iv) {
		args.init->user_iv = iv;
		args.init->user_iv_length = iv_len;
	}

	/*
	 * If tag buffer is defined in the JSON, use this tag buffer for
	 * verification. Even if AEAD_ID is set, the tag saved in the list will be
	 * not be utilized.
	 * If tag buffer is empty, but tag length is defined in the JSON, use this
	 * tag length in the operation.
	 */
	res = set_tag_params(subtest, &tag, &tag_len, args.final, false,
			     tag_field_set);
	if ((res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) ||
	    (!is_api_test(subtest) && res == ERR_CODE(MISSING_PARAMS) &&
	     aead_id == UINT_MAX))
		goto end;

	/* Set output buffer parameters */
	res = set_output_params(subtest, &expected_output, &expected_out_len,
				args.final->tag_length, args.final->data, false,
				tag_field_set);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args,
			      &args.init->key_desc, &args.init->context);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead(aead_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("Buffer too short, expected %u",
				  args.final->data->output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	/* Optional output comparison */
	res = compare_output(args.final, expected_output, expected_out_len);

end:
	if (iv)
		free(iv);

	if (input)
		free(input);

	if (tag)
		free(tag);

	if (args.aad->data)
		free(args.aad->data);

	if (args.final->data->output)
		free(args.final->data->output);

	if (expected_output)
		free(expected_output);

	key_free_key(&key);

	return res;
}

int aead(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	const char *op_type_string = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&op_type_string, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	if (op_type_string && !strcmp(op_type_string, OP_TYPE_ENCRYPT_STR))
		res = aead_encrypt(subtest);
	else
		res = aead_decrypt(subtest);

	return res;
}

int aead_init(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int ctx_id = UINT_MAX;
	struct smw_aead_init_args args = { 0 };
	struct smw_aead_init_args *aead_args = &args;
	struct keypair_ops key = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct tbuffer iv = { 0 };
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;
	unsigned int iv_len = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	res = set_init_params(subtest, &args, &key, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Read IV buffer - Mandatory */
	res = util_read_json_type(&iv, IV_OBJ, t_buffer_hex, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD IV");
		return res;
	}

	util_read_json_type(&iv_len, IV_LEN_OBJ, t_int, subtest->params);
	if (!iv_len)
		iv_len = MAX_IV_LEN;

	args.user_iv = iv.data;
	args.user_iv_length = iv.length;
	args.iv_length = iv_len;

	/* Get AAD length if any */
	res = util_read_json_type(&args.aad_length, AAD_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD AAD length");
		return res;
	}

	res = util_read_json_type(&args.tag_length, TAG_OBJ, t_uint,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND)) {
		DBG_PRINT("Failed to read AEAD tag");
		return res;
	}

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args,
			      &aead_args->key_desc, &aead_args->context);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_init(aead_args);
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
	if (iv.data)
		free(iv.data);

	key_free_key(&key);

	return res;
}

int aead_update_aad(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int ctx_id = UINT_MAX;
	struct smw_aead_aad_args args = { 0 };
	struct smw_aead_aad_args *aead_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read AAD buffer */
	res = util_read_hex_buffer(&args.data, &args.data_length,
				   subtest->params, AAD_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read AEAD buffer");
		goto end;
	}

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args, NULL,
			      &args.context);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_update_aad(aead_args);
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
	if (args.data)
		free(args.data);

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

	res = set_update_output_params(subtest, &expected_output,
				       &expected_out_len, &args);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args, NULL,
			      &args.context);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_update(aead_args);

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
		res = aead_update_save_out_data(subtest, &args, ctx_id);
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

int aead_final(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	unsigned int ctx_id = UINT_MAX;
	struct smw_aead_final_args args = { 0 };
	struct smw_aead_data_args data_args = { 0 };
	struct smw_aead_final_args *aead_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	const char *op_type_string = NULL;
	unsigned int expected_out_len = 0;
	unsigned char *expected_output = NULL;
	unsigned int expected_tag_len = 0;
	unsigned char *expected_tag = NULL;
	bool encrypt_op = false;
	bool tag_field_set = false;

	args.data = &data_args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;
	data_args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.data->context,
				      api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get the operation type - Mandatory */
	res = util_read_json_type(&op_type_string, OP_TYPE_OBJ, t_string,
				  subtest->params);
	if (!is_api_test(subtest) && res != ERR_CODE(PASSED)) {
		DBG_PRINT_MISS_PARAM("AEAD operation type");
		return ERR_CODE(MISSING_PARAMS);
	}

	args.op_type_name = aead_get_op_type_name(op_type_string);

	if (args.op_type_name == SMW_AEAD_OP_TYPE_NAME_ENCRYPT)
		encrypt_op = true;

	if (encrypt_op) {
		res = set_final_output_iv_params(subtest, &args.output_iv,
						 &args.output_iv_length);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			goto end;
	}

	/* Read input if any */
	res = util_read_hex_buffer(&data_args.input, &data_args.input_length,
				   subtest->params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read input buffer");
		goto end;
	}

	/*
	 * If 'tag_field_set' JSON parameter is set to 1, tag will be stored in
	 * dedicated tag field, else
	 * - tag will be a part of output data in case of encryption operation.
	 * - tag will be a part of input data in case of decryption operation.
	 */
	res = util_read_json_type(&tag_field_set, TAG_FIELD_SET_OBJ, t_boolean,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	/* Read Tag buffer, if any */
	res = set_tag_params(subtest, &expected_tag, &expected_tag_len, &args,
			     encrypt_op, tag_field_set);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS)))
		goto end;

	/*
	 * In case of encryption operation,
	 * output = ciphertext + tag (if applicable)
	 *
	 * In case of decryption operation,
	 * output = decrypted ciphertext
	 */

	res = set_output_params(subtest, &expected_output, &expected_out_len,
				args.tag_length, args.data, encrypt_op,
				tag_field_set);
	if (res != ERR_CODE(PASSED))
		goto end;

	/* Specific test cases */
	res = aead_bad_params(subtest->params, (void **)&aead_args, NULL,
			      &args.data->context);
	if (res != ERR_CODE(PASSED))
		goto end;

	subtest->smw_status = smw_aead_final(aead_args);

	if (!args.data->context) {
		res = util_context_update_node(list_op_ctxs(subtest), ctx_id,
					       args.data->context);
		if (res != ERR_CODE(PASSED))
			DBG_PRINT("Failed to update context node data");
	}

	if (subtest->smw_status != SMW_STATUS_OK) {
		if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
			DBG_PRINT("expected  args.data->output_length%u",
				  args.data->output_length);

		res = ERR_CODE(API_STATUS_NOK);
		goto end;
	}

	if (expected_output) {
		res = aead_save_final_output_data(subtest, args.data, ctx_id);
		if (res != ERR_CODE(PASSED))
			goto end;

		res = util_aead_cmp_output_data(list_aeads(subtest), ctx_id,
						expected_output,
						expected_out_len);
		if (res != ERR_CODE(PASSED))
			goto end;
	}

	/*
	 * For encryption operation, compare computed tag with expected tag,
	 * if expected tag is set.
	 */
	if (encrypt_op)
		res = compare_tag(&args, expected_tag, expected_tag_len,
				  tag_field_set);

end:
	if (args.data->input)
		free(args.data->input);

	if (args.data->output)
		free(args.data->output);

	if (expected_output)
		free(expected_output);

	if (args.tag && args.tag != expected_tag)
		free(args.tag);

	if (expected_tag)
		free(expected_tag);

	if (args.output_iv)
		free(args.output_iv);

	return res;
}
