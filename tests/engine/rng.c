// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "types.h"
#include "json_types.h"
#include "crypto.h"
#include "smw_crypto.h"
#include "smw_status.h"

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
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int rng(json_object *params, struct common_parameters *common_params,
	int *ret_status)
{
	int res = ERR_CODE(PASSED);
	unsigned int random_len = 0;
	unsigned char *random_hex = NULL;
	struct smw_rng_args args = { 0 };
	struct smw_rng_args *smw_rng_args = &args;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;

	if (!strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	res = util_read_hex_buffer(&random_hex, &random_len, params,
				   RANDOM_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (!common_params->is_api_test && (!random_len || random_hex)) {
		DBG_PRINT_BAD_ARGS(__func__);
		res = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	if (!common_params->is_api_test) {
		random_hex = malloc(random_len);
		if (!random_hex) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}
		memset(random_hex, 0, random_len);
	}

	args.output = random_hex;
	args.output_length = random_len;

	/* Specific test cases */
	res = set_rng_bad_args(params, &smw_rng_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call RNG function */
	*ret_status = smw_rng(smw_rng_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK && random_hex) {
		if (random_len <= 256) {
			DBG_DHEX("Random number", random_hex, random_len);
		}

		if (!common_params->is_api_test) {
			while (random_len--) {
				if (*(random_hex + random_len))
					goto exit;
			}
			res = ERR_CODE(SUBSYSTEM);
		}
	}

exit:
	if (random_hex)
		free(random_hex);

	return res;
}
