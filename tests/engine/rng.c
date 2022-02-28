// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_crypto.h>

#include "rng.h"
#include "util.h"

/**
 * set_rng_bad_args() - Set RNG bad parameters function of the test error.
 * @params: json-c object.
 * @args: SMW RNG parameters.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_rng_bad_args(json_object *params, struct smw_rng_args **args)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error;

	if (!params || !args)
		return ERR_CODE(BAD_ARGS);

	ret = util_read_test_error(&error, params);
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
	}

	return ret;
}

int rng(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct tbuffer random = { 0 };
	struct smw_rng_args args = { 0 };
	struct smw_rng_args *smw_rng_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = util_read_json_type(&random, RANDOM_OBJ, t_buffer_hex,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (!is_api_test(subtest)) {
		/*
		 * In case of non API test, the test must specify only
		 * the "random" buffer length.
		 */
		if (!random.length || random.data) {
			DBG_PRINT_BAD_PARAM(RANDOM_OBJ);
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto exit;
		}

		random.data = malloc(random.length);
		if (!random.data) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		memset(random.data, 0, random.length);
	}

	args.output = random.data;
	args.output_length = random.length;

	/* Specific test cases */
	res = set_rng_bad_args(subtest->params, &smw_rng_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call RNG function */
	subtest->smw_status = smw_rng(smw_rng_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (!is_api_test(subtest)) {
		if (random.length <= 256)
			DBG_DHEX("Random number", random.data, random.length);

		/* Verify there is not zero value in the random bufffer */
		while (random.length--) {
			if (*(random.data + random.length))
				goto exit;
		}

		res = ERR_CODE(SUBSYSTEM);
	}

exit:
	if (random.data)
		free(random.data);

	return res;
}
