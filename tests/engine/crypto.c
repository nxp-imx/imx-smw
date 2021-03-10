// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "types.h"
#include "crypto.h"
#include "json_types.h"
#include "smw_crypto.h"
#include "smw_status.h"

/**
 * struct hash
 * @algo_name: Hash algo name.
 * @digest_len: @algo_name digest length in bytes.
 */
static struct hash {
	const char *algo_name;
	unsigned int digest_len;
} hash_size[] = { { .algo_name = "MD5", .digest_len = 16 },
		  { .algo_name = "SHA1", .digest_len = 20 },
		  { .algo_name = "SHA224", .digest_len = 28 },
		  { .algo_name = "SHA256", .digest_len = 32 },
		  { .algo_name = "SHA384", .digest_len = 48 },
		  { .algo_name = "SHA512", .digest_len = 64 },
		  { .algo_name = "SM3", .digest_len = 32 },
		  { .algo_name = "UNDEFINED", .digest_len = 20 } };

int get_hash_digest_len(char *algo, unsigned int *len)
{
	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(hash_size);

	if (!algo || !len) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	*len = 0;

	for (; i < array_size; i++) {
		if (!strcmp(algo, hash_size[i].algo_name)) {
			*len = hash_size[i].digest_len;
			break;
		}
	}

	return ERR_CODE(PASSED);
}

/**
 * set_hash_bad_args() - Set hash bad parameters function of the test error.
 * @params: json-c object
 * @smw_hash_args: SMW Hash parameters
 * @digest_hex: expected digest buffer argument parameter
 * @digest_len: expected digest length argument parameter
 * @is_api_test: Test concerns the API validation.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_hash_bad_args(json_object *params, struct smw_hash_args **args,
			     unsigned char *digest_hex, unsigned int digest_len,
			     int is_api_test)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error;

	if (!params)
		return ERR_CODE(BAD_ARGS);

	ret = util_read_test_error(&error, params);
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
		if (is_api_test) {
			(*args)->output = digest_hex;
			(*args)->output_length = digest_len;
		}
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, "test_error");
		ret = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return ret;
}

int hash(json_object *params, struct common_parameters *common_params,
	 char *algo_name, int *ret_status)
{
	int res = ERR_CODE(PASSED);
	unsigned int input_len = 0;
	unsigned int output_len = 0;
	unsigned int digest_len = 0;
	unsigned char *input_hex = NULL;
	unsigned char *output_hex = NULL;
	unsigned char *digest_hex = NULL;
	struct smw_hash_args args = { 0 };
	struct smw_hash_args *smw_hash_args = &args;

	if (!params || !algo_name || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;
	args.algo_name = strlen(algo_name) ? algo_name : NULL;

	if (!strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	res = util_read_hex_buffer(&input_hex, &input_len, params, INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	args.input = input_hex;
	args.input_length = input_len;

	res = get_hash_digest_len((char *)args.algo_name, &output_len);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Output length can be 0. For example: test with a bad algo name
	 * config. In this case don't need to allocate output buffer.
	 */
	if (output_len) {
		output_hex = malloc(output_len);
		if (!output_hex) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}
	}

	args.output = output_hex;
	args.output_length = output_len;

	/*
	 * Read expected digest buffer if any.
	 * Test definition migth not set the expected digest buffer.
	 */
	res = util_read_hex_buffer(&digest_hex, &digest_len, params,
				   DIGEST_OBJ);
	if (res != ERR_CODE(PASSED)) {
		if (res != ERR_CODE(MISSING_PARAMS))
			goto exit;

		res = ERR_CODE(PASSED);
	}

	/* Specific test cases */
	res = set_hash_bad_args(params, &smw_hash_args, digest_hex, digest_len,
				common_params->is_api_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call hash function and compare result with expected one */
	*ret_status = smw_hash(smw_hash_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	/*
	 * If Hash operation succeeded and expected digest is set in the test
	 * definition file then compare operation result.
	 */
	if (*ret_status == SMW_STATUS_OK && digest_hex) {
		if (digest_len != output_len) {
			DBG_PRINT("Bad Digest length got %d expected %d",
				  output_len, digest_len);
			res = ERR_CODE(SUBSYSTEM);
		} else if (memcmp(digest_hex, output_hex, output_len)) {
			DBG_DHEX("Got Digest", output_hex, output_len);
			DBG_DHEX("Expected Digest", digest_hex, digest_len);
			res = ERR_CODE(SUBSYSTEM);
		}
	}

exit:
	if (input_hex)
		free(input_hex);

	if (output_hex)
		free(output_hex);

	if (digest_hex)
		free(digest_hex);

	return res;
}
