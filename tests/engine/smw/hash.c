// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw/names.h>
#include <smw_crypto.h>

#include "hash.h"
#include "json_types.h"
#include "util.h"
#include "util_context.h"

#define HASH_DEF(_name, _len, _is_xof)                                         \
	{                                                                      \
		.name = SMW_HASH_ALGO_NAME_##_name, .string = #_name,          \
		.digest_len = _len, .is_xof = _is_xof                          \
	}

static struct {
	smw_hash_algo_t name;
	const char *string;
	unsigned int digest_len;
	bool is_xof;
} hash_def[] = { HASH_DEF(MD5, 16, false),	HASH_DEF(SHA1, 20, false),
		 HASH_DEF(SHA224, 28, false),	HASH_DEF(SHA256, 32, false),
		 HASH_DEF(SHA384, 48, false),	HASH_DEF(SHA512, 64, false),
		 HASH_DEF(SHA3_224, 28, false), HASH_DEF(SHA3_256, 32, false),
		 HASH_DEF(SHA3_384, 48, false), HASH_DEF(SHA3_512, 64, false),
		 HASH_DEF(SM3, 32, false),	HASH_DEF(SHAKE256, 32, true) };

smw_hash_algo_t hash_get_algo_name(const char *string)
{
	unsigned int i = 0;

	if (!string)
		return SMW_HASH_ALGO_NAME_NONE;

	for (; i < ARRAY_SIZE(hash_def); i++) {
		if (!strcmp(hash_def[i].string, string))
			return hash_def[i].name;
	}

	return SMW_HASH_ALGO_NAME_NB + 1;
}

static int get_hash_digest_len(smw_hash_algo_t name, unsigned int *len)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(hash_def);

	if (name == SMW_HASH_ALGO_NAME_NONE || !len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	*len = 20;

	for (; i < array_size; i++) {
		if (name == hash_def[i].name) {
			*len = hash_def[i].digest_len;
			break;
		}
	}

	return ERR_CODE(PASSED);
}

static int get_check_hash_digest_len(smw_hash_algo_t name, unsigned int len,
				     unsigned int *out_len)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(hash_def);

	if (name == SMW_HASH_ALGO_NAME_NONE || !out_len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	for (; i < array_size; i++) {
		if (name != hash_def[i].name)
			continue;

		/*
		 * In case hash algorithm is an extendable-output
		 * function (XOF), length is variable.
		 * Array hash_def defines the default length in this case.
		 */
		if (hash_def[i].is_xof)
			break;

		if (len != hash_def[i].digest_len) {
			DBG_PRINT("Bad length, got %d expected %d", len,
				  hash_def[i].digest_len);
			return ERR_CODE(SUBSYSTEM);
		}

		*out_len = hash_def[i].digest_len;

		break;
	}

	return ERR_CODE(PASSED);
}

/**
 * set_hash_bad_args() - Set hash bad parameters function of the test error.
 * @subtest: Subtest data
 * @args: SMW Hash parameters.
 * @digest_hex: expected digest buffer argument parameter.
 * @digest_len: expected digest length argument parameter.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_hash_bad_args(struct subtest_data *subtest,
			     struct smw_hash_args **args,
			     unsigned char *digest_hex, unsigned int digest_len)
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
		/*
		 * Test error code is not defined, if it's a test
		 * concerning the hash API, the digest buffer data
		 * and length are defined by the parameter 'digest'
		 * in the test definition file.
		 */
		if (is_api_test(subtest)) {
			(*args)->output = digest_hex;
			(*args)->output_length = digest_len;
		}
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return ret;
}

/**
 * set_hash_init_bad_args() - Set hash init bad parameters function of the test error.
 * @subtest: Subtest data
 * @args: SMW Hash init parameters.
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_hash_init_bad_args(struct subtest_data *subtest,
				  struct smw_hash_init_args **args)
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

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return ret;
}

/**
 * set_hash_update_bad_args() - Set hash update bad parameters function of the test error.
 * @subtest: Subtest data
 * @args: SMW Hash update parameters.
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_hash_update_bad_args(struct subtest_data *subtest,
				    struct smw_hash_update_args **args)
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

	case CTX_NULL:
		(*args)->context = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return ret;
}

/**
 * set_hash_final_bad_args() - Set hash final bad parameters function of the test error.
 * @subtest: Subtest data
 * @args: SMW Hash final parameters.
 * @digest_hex: expected digest buffer argument parameter.
 * @digest_len: expected digest length argument parameter.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_hash_final_bad_args(struct subtest_data *subtest,
				   struct smw_hash_final_args **args,
				   unsigned char *digest_hex,
				   unsigned int digest_len)
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
		/*
		 * Test error code is not defined, if it's a test
		 * concerning the hash API, the digest buffer data
		 * and length are defined by the parameter 'digest'
		 * in the test definition file.
		 */
		if (is_api_test(subtest)) {
			(*args)->output = digest_hex;
			(*args)->output_length = digest_len;
		}
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case CTX_NULL:
		(*args)->context = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return ret;
}

int hash(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	const char *algo_string = NULL;
	unsigned int input_len = 0;
	unsigned int output_len = 0;
	unsigned int digest_len = 0;
	unsigned char *input_hex = NULL;
	unsigned char *output_hex = NULL;
	unsigned char *digest_hex = NULL;
	struct smw_hash_args args = { 0 };
	struct smw_hash_args *smw_hash_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.subsystem_name = subtest->subsystem;

	/* Algorithm is mandatory */
	res = util_read_json_type(&algo_string, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	args.algo_name = hash_get_algo_name(algo_string);

	res = util_read_hex_buffer(&input_hex, &input_len, subtest->params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	args.input = input_hex;
	args.input_length = input_len;

	res = get_hash_digest_len(args.algo_name, &output_len);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Read expected digest buffer if any.
	 * Test definition might not set the expected digest buffer.
	 */
	res = util_read_hex_buffer(&digest_hex, &digest_len, subtest->params,
				   DIGEST_OBJ);
	if (res == ERR_CODE(PASSED))
		output_len = digest_len;
	else if (res == ERR_CODE(MISSING_PARAMS))
		digest_len = output_len;
	else
		goto exit;

	if (output_len) {
		output_hex = malloc(output_len);
		if (!output_hex) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}
	}

	args.output = output_hex;
	args.output_length = output_len;

	/* Specific test cases */
	res = set_hash_bad_args(subtest, &smw_hash_args, digest_hex,
				digest_len);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call hash function and compare result with expected one */
	subtest->smw_status = smw_hash(smw_hash_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	/*
	 * If Hash operation succeeded, check if operation returned
	 * the correct length.
	 */
	res = get_check_hash_digest_len(args.algo_name, args.output_length,
					&digest_len);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_compare_buffers(args.output, args.output_length, digest_hex,
				   digest_len);

exit:
	if (input_hex)
		free(input_hex);

	if (output_hex)
		free(output_hex);

	if (digest_hex)
		free(digest_hex);

	return res;
}

int hash_init(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	const char *algo_string = NULL;
	struct smw_hash_init_args args = { 0 };
	struct smw_hash_init_args *smw_hash_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Algorithm is mandatory */
	res = util_read_json_type(&algo_string, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) &&
	    (!is_api_test(subtest) || res != ERR_CODE(VALUE_NOTFOUND)))
		goto exit;

	args.algo_name = hash_get_algo_name(algo_string);

	/* Specific test cases */
	res = set_hash_init_bad_args(subtest, &smw_hash_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call hash init function */
	subtest->smw_status = smw_hash_init(smw_hash_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

exit:
	return res;
}

int hash_update(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	unsigned int input_len = 0;
	unsigned char *input_hex = NULL;
	struct smw_hash_update_args args = { 0 };
	struct smw_hash_update_args *smw_hash_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_hex_buffer(&input_hex, &input_len, subtest->params,
				   INPUT_OBJ);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(MISSING_PARAMS))) {
		DBG_PRINT("Failed to read input buffer");
		goto exit;
	}

	args.input = input_hex;
	args.input_length = input_len;

	/* Specific test cases */
	res = set_hash_update_bad_args(subtest, &smw_hash_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call hash update function */
	subtest->smw_status = smw_hash_update(smw_hash_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

exit:
	if (input_hex)
		free(input_hex);

	return res;
}

int hash_final(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	unsigned int ctx_id = UINT_MAX;
	const char *algo_string = NULL;
	smw_hash_algo_t algo_name = SMW_HASH_ALGO_NAME_NONE;
	unsigned int input_len = 0;
	unsigned int output_len = 0;
	unsigned int digest_len = 0;
	unsigned char *input_hex = NULL;
	unsigned char *output_hex = NULL;
	unsigned char *digest_hex = NULL;
	struct smw_hash_final_args args = { 0 };
	struct smw_hash_final_args *smw_hash_args = &args;
	struct smw_op_context *api_ctx = (struct smw_op_context *)INTPTR_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	res = util_context_set_op_ctx(subtest, &ctx_id, &args.context, api_ctx);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Algorithm is mandatory */
	res = util_read_json_type(&algo_string, ALGO_OBJ, t_string,
				  subtest->params);
	if ((!is_api_test(subtest) && res != ERR_CODE(PASSED)) ||
	    (is_api_test(subtest) && res != ERR_CODE(PASSED) &&
	     res != ERR_CODE(VALUE_NOTFOUND))) {
		DBG_PRINT("Failed to read algorithm");
		goto exit;
	}

	algo_name = hash_get_algo_name(algo_string);

	res = util_read_hex_buffer(&input_hex, &input_len, subtest->params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS)) {
		DBG_PRINT("Failed to read input buffer");
		goto exit;
	}

	args.input = input_hex;
	args.input_length = input_len;

	if (!is_api_test(subtest)) {
		res = get_hash_digest_len(algo_name, &output_len);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	/*
	 * Read expected digest buffer if any.
	 * Test definition might not set the expected digest buffer.
	 */
	res = util_read_hex_buffer(&digest_hex, &digest_len, subtest->params,
				   DIGEST_OBJ);
	if (res == ERR_CODE(PASSED))
		output_len = digest_len;
	else if (res == ERR_CODE(MISSING_PARAMS))
		digest_len = output_len;
	else
		goto exit;

	if (output_len) {
		output_hex = malloc(output_len);
		if (!output_hex) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}
	}

	args.output = output_hex;
	args.output_length = output_len;

	/* Specific test cases */
	res = set_hash_final_bad_args(subtest, &smw_hash_args, digest_hex,
				      digest_len);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call hash final function */
	subtest->smw_status = smw_hash_final(smw_hash_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (!is_api_test(subtest)) {
		/*
		 * If Hash operation succeeded, check if operation returned
		 * the correct length.
		 */
		res = get_check_hash_digest_len(algo_name, args.output_length,
						&digest_len);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	res = util_compare_buffers(args.output, args.output_length, digest_hex,
				   digest_len);

exit:
	if (input_hex)
		free(input_hex);

	if (output_hex)
		free(output_hex);

	if (digest_hex)
		free(digest_hex);

	return res;
}
