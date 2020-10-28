// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
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
		  { .algo_name = "SM3", .digest_len = 32 } };

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

int hash(json_object *params, struct common_parameters *common_params,
	 char *algo_type, int *ret_status)
{
	int res = ERR_CODE(PASSED);
	unsigned int output_len = 0;
	char *input_string = NULL;
	char *digest_string = NULL;
	unsigned char *hex_message = NULL;
	unsigned char *output = NULL;
	unsigned char *expected_digest = NULL;
	enum arguments_test_err_case test_error = NB_ERROR_CASE;
	struct smw_hash_args args = { 0 };
	struct smw_hash_args *smw_hash_args = NULL;
	json_object *digest_obj = NULL;
	json_object *input_obj = NULL;
	json_object *test_err_obj = NULL;

	if (!params || !algo_type || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* Specific test cases */
	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &test_err_obj)) {
		/*
		 * If test error is ARGS_NULL nothing has to be done. This
		 * case call smw_hash with NULL argument.
		 */
		res = get_test_err_status(&test_error,
					  json_object_get_string(test_err_obj));
		if (res != ERR_CODE(PASSED))
			return res;

		if (test_error != ARGS_NULL) {
			DBG_PRINT_BAD_PARAM(__func__, "test_error");
			return ERR_CODE(BAD_PARAM_TYPE);
		}
	} else {
		args.version = common_params->version;
		args.algo_name = algo_type;

		if (!strcmp(common_params->subsystem, "DEFAULT"))
			args.subsystem_name = NULL;
		else
			args.subsystem_name = common_params->subsystem;

		/* 'input' is an optional parameter */
		if (json_object_object_get_ex(params, INPUT_OBJ, &input_obj)) {
			input_string =
				(char *)json_object_get_string(input_obj);
			res = convert_string_to_hex(input_string, &hex_message);
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT("Can't convert message: %d", res);
				return res;
			}

			args.input = hex_message;
			args.input_length = strlen((char *)hex_message);
		}

		res = get_hash_digest_len((char *)args.algo_name, &output_len);
		if (res != ERR_CODE(PASSED))
			goto exit;

		/*
		 * Output len can be 0. For example: test with a bad algo name
		 * config. In this case don't need to allocate output buffer.
		 */
		if (output_len) {
			output = malloc(output_len);
			if (!output) {
				DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		args.output = output;
		args.output_length = output_len;
		smw_hash_args = &args;
	}

	/* Call hash function and compare result with expected one */
	*ret_status = smw_hash(smw_hash_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	/*
	 * If Hash operation succeeded and digest and input are set in the test
	 * definition file then compare operation result.
	 */
	if (*ret_status == SMW_STATUS_OK && hex_message &&
	    json_object_object_get_ex(params, DIGEST_OBJ, &digest_obj)) {
		digest_string = (char *)json_object_get_string(digest_obj);
		res = convert_string_to_hex(digest_string, &expected_digest);
		if (res != ERR_CODE(PASSED)) {
			DBG_PRINT("Can't convert digest: %d", res);
			goto exit;
		}

		if (strcmp((char *)expected_digest, (char *)output)) {
			DBG_PRINT("Digest is bad");
			res = ERR_CODE(SUBSYSTEM);
		}
	} else {
		res = ERR_CODE(PASSED);
	}

exit:
	if (hex_message)
		free(hex_message);

	if (output)
		free(output);

	if (expected_digest)
		free(expected_digest);

	return res;
}
