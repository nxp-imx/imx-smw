// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "util.h"
#include "util_mac.h"

#include "key.h"
#include "hash.h"
#include "mac.h"

#define MAC_ALGO(_name, _id, _trunc)                                           \
	{                                                                      \
		.name = #_name, .psa_alg_id = _id, .truncated = _trunc         \
	}

/**
 * struct mac_alg_info
 * @name: MAC algo name.
 * @psa_alg_id: PSA MAC algo id.
 */
static struct mac_alg_info {
	const char *name;
	psa_algorithm_t psa_alg_id;
	bool truncated;
} mac_alg_info[] = { MAC_ALGO(HMAC, PSA_ALG_HMAC_BASE, false),
		     MAC_ALGO(HMAC_TRUNCATED, PSA_ALG_HMAC_BASE, true),
		     MAC_ALGO(CMAC, PSA_ALG_CMAC, false),
		     MAC_ALGO(CMAC_TRUNCATED, PSA_ALG_CMAC, true),
		     { .name = NULL, .psa_alg_id = PSA_ALG_NONE } };

static struct mac_alg_info *get_mac_alg_info(const char *alg_name)
{
	return GET_INFO(alg_name, mac_alg_info);
}

int mac_psa(struct subtest_data *subtest, bool verify)
{
	int res = ERR_CODE(PASSED);
	const char *key_name = NULL;
	struct keypair_psa key_test = { 0 };
	const char *alg_name = NULL;
	const char *hash_name = NULL;
	struct mac_alg_info *mac_alg_info = NULL;
	psa_algorithm_t hash_alg_id = PSA_ALG_NONE;
	psa_algorithm_t psa_alg_id = PSA_ALG_NONE;
	int mac_id = INT_MAX;
	unsigned char *input = NULL;
	unsigned int input_length = 0;
	unsigned char *output = NULL;
	unsigned int output_length = 0;
	unsigned char *mac = NULL;
	unsigned int mac_size = 0;
	size_t mac_length = 0;
	unsigned char *expected_mac = NULL;
	unsigned int expected_mac_length = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_test.data)
		free(key_test.data);

	res = util_read_hex_buffer(&output, &output_length, subtest->params,
				   OUTPUT_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* MAC algorithm */
	res = util_read_json_type(&alg_name, ALGO_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	mac_alg_info = get_mac_alg_info(alg_name);
	if (!mac_alg_info) {
		res = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	psa_alg_id = mac_alg_info->psa_alg_id;

	if (psa_alg_id == PSA_ALG_HMAC_BASE) {
		/* Hash algorithm */
		res = util_read_json_type(&hash_name, HASH_OBJ, t_string,
					  subtest->params);
		if (res != ERR_CODE(PASSED) || !hash_name)
			goto exit;

		hash_alg_id = get_hash_alg_id(hash_name);

		psa_alg_id = PSA_ALG_HMAC(hash_alg_id);
	}

	res = util_read_hex_buffer(&input, &input_length, subtest->params,
				   INPUT_OBJ);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Read expected mac buffer if any.
	 * Test definition might not set the expected mac buffer.
	 */
	res = util_read_hex_buffer(&expected_mac, &expected_mac_length,
				   subtest->params, MAC_OBJ);
	if (res != ERR_CODE(PASSED)) {
		if (res != ERR_CODE(MISSING_PARAMS))
			goto exit;

		res = ERR_CODE(PASSED);
	}

	/* Get 'mac_id' parameter to store the mac in the list */
	res = util_read_json_type(&mac_id, MAC_ID_OBJ, t_int, subtest->params);
	if (res != ERR_CODE(PASSED)) {
		if (res != ERR_CODE(VALUE_NOTFOUND))
			goto exit;

		res = ERR_CODE(PASSED);
	}

	if (verify) {
		if (mac_id != INT_MAX) {
			res = util_mac_find_node(list_macs(subtest), mac_id,
						 &mac, &mac_size);

			/* 'mac_id' is set and must be present in the list */
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(MAC_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}
		} else {
			mac = expected_mac;
			mac_size = expected_mac_length;
		}

		if (mac_alg_info->truncated)
			psa_alg_id =
				PSA_ALG_TRUNCATED_MAC(psa_alg_id, mac_size);

		subtest->psa_status =
			psa_mac_verify(key_test.attributes.id, psa_alg_id,
				       input, input_length, mac, mac_size);
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

		/*
		 * If output length is set but there is no buffer, allocate it.
		 * Otherwise it's allocated by the util_read_hex_buffer()
		 * function.
		 */
		if (output_length && !output) {
			output = malloc(output_length);
			if (!output) {
				DBG_PRINT_ALLOC_FAILURE();
				res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				goto exit;
			}
		}

		mac = output;
		mac_size = output_length;

		if (mac_alg_info->truncated)
			psa_alg_id =
				PSA_ALG_TRUNCATED_MAC(psa_alg_id, mac_size);

		subtest->psa_status =
			psa_mac_compute(key_test.attributes.id, psa_alg_id,
					input, input_length, mac, mac_size,
					&mac_length);
		if (subtest->psa_status != PSA_SUCCESS) {
			if (subtest->psa_status == PSA_ERROR_BUFFER_TOO_SMALL)
				DBG_PRINT("Buffer too short, expected %u",
					  mac_length);
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
		if (expected_mac && mac_id == INT_MAX) {
			res = util_compare_buffers(expected_mac,
						   expected_mac_length, mac,
						   mac_length);
		} else if (mac_id != INT_MAX) {
			res = util_mac_add_node(list_macs(subtest), mac_id, mac,
						mac_length);
			/* Don't free output MAC generated */
			if (res == ERR_CODE(PASSED))
				output = NULL;
		}
	}

exit:
	if (input)
		free(input);

	if (output)
		free(output);

	if (expected_mac)
		free(expected_mac);

	return res;
}
