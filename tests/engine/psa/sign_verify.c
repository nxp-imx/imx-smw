// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "util.h"
#include "util_attr.h"
#include "util_sign.h"

#include "key.h"
#include "sign_verify.h"

int sign_verify_psa(struct subtest_data *subtest, int operation)
{
	int res = ERR_CODE(PASSED);
	struct keypair_psa key_test = { 0 };
	const char *key_name = NULL;
	psa_algorithm_t psa_alg_id = PSA_ALG_NONE;
	int sign_id = INT_MAX;
	unsigned int message_length = 0;
	unsigned int list_sign_length = 0;
	unsigned int output_length = 0;
	unsigned int exp_sign_length = 0;
	unsigned int signature_size = 0;
	size_t signature_length = 0;
	unsigned char *message = NULL;
	unsigned char *list_sign = NULL;
	unsigned char *output = NULL;
	unsigned char *exp_sign = NULL;
	unsigned char *signature = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (operation != SIGN_OPERATION && operation != VERIFY_OPERATION)
		return ERR_CODE(UNDEFINED_CMD);

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

	/* Signature attributes are not mandatory in case of error test */
	res = util_attr_read_attributes(subtest->params, SIGN_ATTR_OBJ,
					&algorithm_callback_psa, &psa_alg_id);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Read message buffer if any */
	res = util_read_hex_buffer(&message, &message_length, subtest->params,
				   MESS_OBJ);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	/* Get 'sign_id' parameter */
	res = util_read_json_type(&sign_id, SIGN_ID_OBJ, t_int,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (sign_id != INT_MAX) {
		res = util_sign_find_node(list_signatures(subtest), sign_id,
					  &list_sign, &list_sign_length);

		if (operation == SIGN_OPERATION) {
			/* 'sign_id' must not be in the signatures list */
			if (res == ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(SIGN_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}

			if (output_length && !output) {
				output = malloc(output_length);
				if (!output) {
					DBG_PRINT_ALLOC_FAILURE();
					res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
					goto exit;
				}
			}

			signature = output;
			signature_size = output_length;
		} else /* operation == VERIFY_OPERATION */ {
			/* 'sign_id' must be in the signatures list */
			if (res != ERR_CODE(PASSED)) {
				DBG_PRINT_BAD_PARAM(SIGN_ID_OBJ);
				res = ERR_CODE(BAD_PARAM_TYPE);
				goto exit;
			}

			signature = list_sign;
			signature_size = list_sign_length;
		}
	}

	/* Read expected signature buffer if any */
	res = util_read_hex_buffer(&exp_sign, &exp_sign_length, subtest->params,
				   SIGN_OBJ);
	if (res != ERR_CODE(PASSED)) {
		if (res != ERR_CODE(MISSING_PARAMS))
			goto exit;

		res = ERR_CODE(PASSED);
	}

	/* Call operation function and compare result with expected one */
	if (operation == SIGN_OPERATION) {
		if (PSA_ALG_GET_HASH(psa_alg_id) != PSA_ALG_NONE)
			subtest->psa_status =
				psa_sign_message(key_test.attributes.id,
						 psa_alg_id, message,
						 message_length, signature,
						 signature_size,
						 &signature_length);
		else
			subtest->psa_status =
				psa_sign_hash(key_test.attributes.id,
					      psa_alg_id, message,
					      message_length, signature,
					      signature_size,
					      &signature_length);

	} else { /* operation == VERIFY_OPERATION */
		if (PSA_ALG_GET_HASH(psa_alg_id) != PSA_ALG_NONE)
			subtest->psa_status =
				psa_verify_message(key_test.attributes.id,
						   psa_alg_id, message,
						   message_length, signature,
						   signature_size);
		else
			subtest->psa_status =
				psa_verify_hash(key_test.attributes.id,
						psa_alg_id, message,
						message_length, signature,
						signature_size);
	}

	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (operation == SIGN_OPERATION) {
		if (!signature) {
			if (signature_length != exp_sign_length) {
				DBG_PRINT("Bad Sign length got %d expected %d",
					  signature_length, exp_sign_length);
				res = ERR_CODE(SUBSYSTEM);
			}

			goto exit;
		}

		/* Store signature */
		res = util_sign_add_node(list_signatures(subtest), sign_id,
					 signature, signature_length);
		if (res)
			signature = NULL;
	}

exit:
	if (message)
		free(message);

	if (output && output != signature)
		free(output);

	if (exp_sign)
		if (operation != SIGN_OPERATION || exp_sign != signature)
			free(exp_sign);

	return res;
}
