// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_keymgr.h>
#include <smw_crypto.h>

#include "util.h"
#include "util_mac.h"

#include "key.h"
#include "mac.h"

/**
 * set_mac_bad_args() - Set MAC bad parameters function of the test error.
 * @subtest: Subtest data
 * @args: SMW MAC parameters.
 * @mac_hex: expected mac buffer argument parameter.
 * @mac_len: expected mac length argument parameter.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_mac_bad_args(struct subtest_data *subtest,
			    struct smw_mac_args **args, unsigned char *mac_hex,
			    unsigned int mac_len)
{
	int ret = ERR_CODE(PASSED);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!subtest || !args)
		return ERR_CODE(BAD_ARGS);

	/*
	 * In case of API test, the parameter "mac"
	 * can explicitly define the mac buffer.
	 * Otherwise it is ignored.
	 */
	if (is_api_test(subtest)) {
		/*
		 * The mac buffer may have been already allocated.
		 */
		(*args)->mac = mac_hex;
		(*args)->mac_length = mac_len;
	}

	ret = util_read_test_error(&error, subtest->params);
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
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

int mac(struct subtest_data *subtest, bool verify)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	const char *key_name = NULL;
	struct smw_keypair_buffer key_buffer = { 0 };
	int mac_id = INT_MAX;
	unsigned int input_len = 0;
	unsigned int output_len = 0;
	unsigned int mac_len = 0;
	unsigned char *input_hex = NULL;
	unsigned char *output_hex = NULL;
	unsigned char *mac_hex = NULL;
	struct smw_mac_args args = { 0 };
	struct smw_mac_args *smw_mac_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (subtest->subsystem && !strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Initialize key descriptor */
	res = key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_is_id_set(&key_test))
		key_free_key(&key_test);

	if (!key_is_id_set(&key_test) &&
	    (!key_is_type_set(&key_test) || !key_is_security_set(&key_test) ||
	     !key_is_private_key_defined(&key_test))) {
		DBG_PRINT_MISS_PARAM("Key description");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Algorithm is not mandatory in case of error test */
	res = util_read_json_type(&args.algo_name, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Hash algorithm is not mandatory*/
	res = util_read_json_type(&args.hash_name, HASH_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = util_read_hex_buffer(&input_hex, &input_len, subtest->params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	args.input = input_hex;
	args.input_length = input_len;

	/*
	 * Read expected mac buffer if any.
	 * Test definition might not set the expected mac buffer.
	 */
	res = util_read_hex_buffer(&mac_hex, &mac_len, subtest->params,
				   MAC_OBJ);
	if (res != ERR_CODE(PASSED)) {
		if (res != ERR_CODE(MISSING_PARAMS))
			goto exit;

		res = ERR_CODE(PASSED);
	}

	/* Get 'mac_id' parameter to store the mac in the list */
	res = util_read_json_type(&mac_id, MAC_ID_OBJ, t_int, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (verify) {
		if (mac_id != INT_MAX) {
			res = util_mac_find_node(list_macs(subtest), mac_id,
						 &args.mac, &args.mac_length);

			/* 'mac_id' is set and must be present in the list */
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(MAC_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}
		} else {
			args.mac = mac_hex;
			args.mac_length = mac_len;
		}
	} else {
		if (mac_id != INT_MAX) {
			res = util_mac_find_node(list_macs(subtest), mac_id,
						 NULL, NULL);
			/*
			 * 'mac_id' is set and must not be present
			 * in the list
			 */
			if (res == ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(MAC_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}
		}

		res = util_read_hex_buffer(&output_hex, &output_len,
					   subtest->params, OUTPUT_OBJ);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
			goto exit;

		/*
		 * If output length is set but there is no buffer, allocate it.
		 * Otherwise it's allocated by the util_read_hex_buffer()
		 * function.
		 */
		if (output_len && !output_hex) {
			output_hex = malloc(output_len);
			if (!output_hex) {
				DBG_PRINT_ALLOC_FAILURE();
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		args.mac = output_hex;
		args.mac_length = output_len;
	}

	/* Specific test cases */
	res = set_mac_bad_args(subtest, &smw_mac_args, mac_hex, mac_len);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (verify) {
		subtest->smw_status = smw_mac_verify(smw_mac_args);
	} else {
		/* Call cmac function and compare result with expected one */
		subtest->smw_status = smw_mac(smw_mac_args);
		if (subtest->smw_status != SMW_STATUS_OK) {
			if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT)
				DBG_PRINT("Buffer too short, expected %u",
					  smw_mac_args->mac_length);
			res = ERR_CODE(API_STATUS_NOK);
			goto exit;
		}

		/*
		 * If MAC operation succeeded:
		 * - case 1 (no mac_id defined but expected mac):
		 *       expected mac is set in the test definition file then
		 *       compare operation result.
		 *
		 * - case 2 (mac_id defined):
		 *       store the generated mac in the list.
		 *
		 * - case 3 (no mac_id and no expected mac):
		 *       nothing to do.
		 */
		if (mac_hex && mac_id == INT_MAX) {
			res = util_compare_buffers(args.mac, args.mac_length,
						   mac_hex, mac_len);
		} else if (mac_id != INT_MAX) {
			res = util_mac_add_node(list_macs(subtest), mac_id,
						args.mac, args.mac_length);
			/* Don't free output MAC generated */
			if (res == ERR_CODE(PASSED))
				output_hex = NULL;
		}
	}

exit:
	key_free_key(&key_test);

	if (input_hex)
		free(input_hex);

	if (output_hex)
		free(output_hex);

	if (mac_hex)
		free(mac_hex);

	return res;
}
