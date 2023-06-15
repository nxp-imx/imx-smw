// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

#include "util.h"
#include "util_key.h"

#include "key.h"

#define KEY_JSON_OBJECT_STRING_MAX_LEN 10

/**
 * compare_keys() - Compare PSA keys with expected keys
 * @data: Buffer where the key data has been written
 * @data_length: Length of @data
 * @exp_data: Expected key data
 * @exp_data_length: Length of @exp_data
 *
 * Function compares private key if expected key private data set.
 * Same if expected key public data set, compare public key.
 *
 * Return:
 * PASSED      - Success.
 * -SUBSYSTEM  - One of the keys is not correct
 */
static int compare_keys(uint8_t *data, size_t data_length, uint8_t *exp_data,
			size_t exp_data_length)
{
	/*
	 * If test is to compare exported key with
	 * the one set in the test definition, do
	 * the comparaison.
	 */
	return util_compare_buffers(data, data_length, exp_data,
				    exp_data_length);
}

/**
 * compare_attributes() - Compare PSA key attributes with expected key attributes
 * @attributes: Key attributes written by subsystem
 * @exp_attributes: Expected key attributes
 *
 * Function compares key attributes.
 *
 * Return:
 * PASSED      - Success.
 * -SUBSYSTEM  - One of the key attributes is not correct
 */
static int compare_attributes(psa_key_attributes_t *attributes,
			      psa_key_attributes_t *exp_attributes)
{
	int res = ERR_CODE(SUBSYSTEM);
	int err = 0;

	psa_key_persistence_t persistence;
	psa_key_persistence_t exp_persistence;

	if (attributes->id != exp_attributes->id) {
		DBG_PRINT("Bad key ID, got %d expected %d", attributes->id,
			  exp_attributes->id);
		err = 1;
	}

	if (attributes->type != exp_attributes->type) {
		DBG_PRINT("Bad key type, got %x expected %x", attributes->type,
			  exp_attributes->type);
		err = 1;
	}

	if (attributes->bits != exp_attributes->bits) {
		DBG_PRINT("Bad key bits, got %d expected %d", attributes->bits,
			  exp_attributes->bits);
		err = 1;
	}

	persistence = PSA_KEY_LIFETIME_GET_PERSISTENCE(attributes->lifetime);
	exp_persistence =
		PSA_KEY_LIFETIME_GET_PERSISTENCE(exp_attributes->lifetime);
	if (persistence != exp_persistence) {
		DBG_PRINT("Bad key persistence, got %x expected %x",
			  persistence, exp_persistence);
		err = 1;
	}

	if (attributes->alg && attributes->alg != exp_attributes->alg) {
		DBG_PRINT("Bad key algorithm, got %x expected %x",
			  attributes->alg, exp_attributes->alg);
		err = 1;
	}

	if ((attributes->usage_flags & exp_attributes->usage_flags) !=
	    exp_attributes->usage_flags) {
		DBG_PRINT("Bad key usage flags, got %x expected %x",
			  attributes->usage_flags, exp_attributes->usage_flags);
		err = 1;
	}

	if (!err)
		res = ERR_CODE(PASSED);

	return res;
}

int generate_key_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_psa key_test = { 0 };
	struct key_data key_data = { 0 };
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Initialize key descriptor */
	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (key_test.data)
		free(key_test.data);

	/* Call generate key function and compare result with expected one */
	subtest->psa_status =
		psa_generate_key(&key_test.attributes, &key_test.attributes.id);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	key_prepare_key_data_psa(&key_test, &key_data);
	res = util_key_update_node(list_keys(subtest), key_name, &key_data);

exit:
	return res;
}

int delete_key_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(FAILED);
	struct keypair_psa key_test = { 0 };
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Initialize key descriptor */
	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_test.data)
		free(key_test.data);

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Call delete key function and compare result with expected one */
	subtest->psa_status = psa_destroy_key(key_test.attributes.id);
	if (subtest->psa_status != PSA_SUCCESS)
		return ERR_CODE(API_STATUS_NOK);

	/*
	 * Key node is freed when the list is freed (at the of the test).
	 * Even if the key is deleted by the subsystem a test scenario
	 * can try to delete/use it after this operation.
	 */

	return ERR_CODE(PASSED);
}

int import_key_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_psa key_test = { 0 };
	struct key_data key_data = { 0 };
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Initialize key descriptor */
	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call import key function and compare result with expected one */
	subtest->psa_status =
		psa_import_key(&key_test.attributes, key_test.data,
			       key_test.data_length, &key_test.attributes.id);
	if (subtest->psa_status != PSA_SUCCESS) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	key_prepare_key_data_psa(&key_test, &key_data);
	res = util_key_update_node(list_keys(subtest), key_name, &key_data);

exit:
	if (key_test.data)
		free(key_test.data);

	return res;
}

int export_key_psa(struct subtest_data *subtest, enum export_type export_type)
{
	int res = ERR_CODE(PASSED);
	struct keypair_psa key_test = { 0 };
	struct keypair_psa exp_key_test = { 0 };
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Initialize 2 key descriptors:
	 *  - one with the expected key buffers if private/public keys
	 *    are defined in the test definition file.
	 *  - one use for the export key operation.
	 */
	/* Initialize expected keys */
	res = key_desc_init_psa(&exp_key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &exp_key_test,
				      key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call export key function and compare result with expected one */
	if (export_type == EXP_PUB)
		subtest->psa_status =
			psa_export_public_key(key_test.attributes.id,
					      key_test.data,
					      key_test.data_length,
					      &key_test.data_length);
	else
		subtest->psa_status =
			psa_export_key(key_test.attributes.id, key_test.data,
				       key_test.data_length,
				       &key_test.data_length);

	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

	if (subtest->psa_status == PSA_SUCCESS) {
		if (exp_key_test.data && !exp_key_test.data[0]) {
			free(exp_key_test.data);
			exp_key_test.data = NULL;
		}
		res = compare_keys(key_test.data, key_test.data_length,
				   exp_key_test.data, exp_key_test.data_length);
	}

exit:
	if (key_test.data)
		free(key_test.data);

	if (exp_key_test.data)
		free(exp_key_test.data);

	return res;
}

int get_key_attributes_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(FAILED);
	struct keypair_psa key_test = { 0 };
	psa_key_attributes_t psa_key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Initialize key descriptor */
	res = key_desc_init_psa(&key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor_psa(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	if (key_test.data)
		free(key_test.data);

	subtest->psa_status = psa_get_key_attributes(key_test.attributes.id,
						     &psa_key_attributes);
	if (subtest->psa_status != PSA_SUCCESS)
		return ERR_CODE(API_STATUS_NOK);

	res = compare_attributes(&psa_key_attributes, &key_test.attributes);

	return res;
}
