// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "types.h"
#include "json_types.h"
#include "keymgr.h"
#include "crypto.h"
#include "smw_keymgr.h"
#include "smw_crypto.h"
#include "smw_status.h"

/**
 * set_hmac_bad_args() - Set hmac bad parameters function of the test error.
 * @params: json-c object.
 * @args: SMW HMAC parameters.
 * @mac_hex: expected mac buffer argument parameter.
 * @mac_len: expected mac length argument parameter.
 * @is_api_test: Test concerns the API validation.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_hmac_bad_args(json_object *params, struct smw_hmac_args **args,
			     unsigned char *mac_hex, unsigned int mac_len,
			     int is_api_test)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error;

	if (!params || !args)
		return ERR_CODE(BAD_ARGS);

	/*
	 * In case of API test, the parameter "mac"
	 * can explicitly define the mac buffer.
	 * Otherwise it is ignored.
	 */
	if (is_api_test) {
		/*
		 * The mac buffer may have been already allocated.
		 */
		(*args)->output = mac_hex;
		(*args)->output_length = mac_len;
	}

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case KEY_DESC_NULL:
		(*args)->key_descriptor = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int hmac(json_object *params, struct common_parameters *common_params,
	 char *algo_name, struct key_identifier_list *key_identifiers,
	 int *ret_status)
{
	int res = ERR_CODE(PASSED);
	int status = SMW_STATUS_OPERATION_FAILURE;
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	int key_id = INT_MAX;
	unsigned int input_len = 0;
	unsigned int output_len = 0;
	unsigned int mac_len = 0;
	unsigned char *input_hex = NULL;
	unsigned char *output_hex = NULL;
	unsigned char *mac_hex = NULL;
	struct smw_hmac_args args = { 0 };
	struct smw_hmac_args *smw_hmac_args = &args;

	if (!params || !algo_name || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;

	if (!strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Initialize key descriptor */
	res = util_key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, params);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_id != INT_MAX) {
		util_key_free_key(&key_test);
		key_test.desc.buffer = NULL;
		key_test.keys = NULL;
		util_key_set_ops(&key_test);

		/* Fill key descriptor field saved */
		res = util_key_find_key_node(key_identifiers, key_id,
					     &key_test);
		if (res != ERR_CODE(PASSED))
			goto exit;

		/*
		 * If Security size not set,
		 * get it from the SMW key identifier
		 */
		if (!util_key_is_security_set(&key_test)) {
			status = smw_get_security_size(&key_test.desc);
			if (status != SMW_STATUS_OK) {
				res = ERR_CODE(BAD_RESULT);
				goto exit;
			}
		}
	} else if (!util_key_is_type_set(&key_test) ||
		   !util_key_is_security_set(&key_test) ||
		   !util_key_is_private_key_defined(&key_test)) {
		DBG_PRINT_MISS_PARAM(__func__, "Key description");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	args.algo_name = strlen(algo_name) ? algo_name : NULL;

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
	 * Read expected mac buffer if any.
	 * Test definition might not set the expected mac buffer.
	 */
	res = util_read_hex_buffer(&mac_hex, &mac_len, params, MAC_OBJ);
	if (res != ERR_CODE(PASSED)) {
		if (res != ERR_CODE(MISSING_PARAMS))
			goto exit;

		res = ERR_CODE(PASSED);
	}

	/* Specific test cases */
	res = set_hmac_bad_args(params, &smw_hmac_args, mac_hex, mac_len,
				common_params->is_api_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call hmac function and compare result with expected one */
	*ret_status = smw_hmac(smw_hmac_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	/*
	 * If HMAC operation succeeded and expected mac is set in the test
	 * definition file then compare operation result.
	 */
	if (*ret_status == SMW_STATUS_OK && mac_hex) {
		if (mac_len != output_len) {
			DBG_PRINT("Bad Mac length got %d expected %d",
				  output_len, mac_len);
			res = ERR_CODE(SUBSYSTEM);
		} else if (memcmp(mac_hex, output_hex, output_len)) {
			DBG_DHEX("Got Mac", output_hex, output_len);
			DBG_DHEX("Expected Mac", mac_hex, mac_len);
			res = ERR_CODE(SUBSYSTEM);
		}
	}

exit:
	util_key_free_key(&key_test);

	if (input_hex)
		free(input_hex);

	if (output_hex)
		free(output_hex);

	if (mac_hex)
		free(mac_hex);

	return res;
}
