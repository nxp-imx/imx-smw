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
		  { .algo_name = "UNDEFINED", .digest_len = 1 } };

/**
 * get_hash_digest_len() - Return digest byte length switch algorithm.
 * @algo: Algorithm name.
 * @len: Pointer to digest length to update. Set to 0 if @algo is not found
 *       in @hash_size.
 *
 * Call this function with an undefined algo value is not an error.
 *
 * Return:
 * PASSED	- Success.
 * -BAD_ARGS	- One of the arguments is bad.
 */
static int get_hash_digest_len(char *algo, unsigned int *len)
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
 * set_bad_args() - Set hash bad parameters function of the test error.
 * @error: Test error id.
 * @smw_hash_args: SMW Hash parameters
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_bad_args(enum arguments_test_err_case error,
			struct smw_hash_args **smw_hash_args)
{
	int ret = ERR_CODE(PASSED);
	struct smw_hash_args *args = *smw_hash_args;

	switch (error) {
	case ARGS_NULL:
		*smw_hash_args = NULL;
		break;

	case BAD_VERSION:
	case BAD_SUBSYSTEM:
	case BAD_ALGO:
		args->output_length = 10;
		args->output = malloc(args->output_length);
		if (!args->output)
			ret = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		break;

	case DIGEST_BUFFER_NULL:
		args->output = NULL;
		args->output_length = 1;
		break;

	case DIGEST_LENGTH_ZERO:
		args->output = malloc(10);
		if (!args->output)
			ret = ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		args->output_length = 0;
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
	json_object *test_err_obj = NULL;
	enum arguments_test_err_case test_error = NB_ERROR_CASE;
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

	/* Specific test cases */
	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &test_err_obj)) {
		res = get_test_err_status(&test_error,
					  json_object_get_string(test_err_obj));
		if (res != ERR_CODE(PASSED))
			return res;

		res = set_bad_args(test_error, &smw_hash_args);
		if (res != ERR_CODE(PASSED))
			return res;
	} else {
		res = util_read_hex_buffer(&input_hex, &input_len, params,
					   INPUT_OBJ);
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
	}

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
	if (*ret_status == SMW_STATUS_OK && input_hex) {
		res = util_read_hex_buffer(&digest_hex, &digest_len, params,
					   DIGEST_OBJ);
		if (res == ERR_CODE(MISSING_PARAMS)) {
			/* Expected digest not set */
			res = ERR_CODE(PASSED);
			goto exit;
		}

		if (res == ERR_CODE(PASSED)) {
			if (digest_len != output_len) {
				DBG_PRINT("Bad Digest length got %d expected %d",
					  output_len, digest_len);
				res = ERR_CODE(SUBSYSTEM);
			} else if (memcmp(digest_hex, output_hex, output_len)) {
				DBG_DHEX("Got Digest", output_hex, output_len);
				DBG_DHEX("Expected Digest", digest_hex,
					 digest_len);
				res = ERR_CODE(SUBSYSTEM);
			}
		}
	}

exit:
	if (input_hex)
		free(input_hex);

	if (args.output)
		free(args.output);

	if (digest_hex)
		free(digest_hex);

	return res;
}
