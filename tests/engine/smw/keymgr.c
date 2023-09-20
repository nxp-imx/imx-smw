// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <smw_keymgr.h>

#include "util.h"
#include "util_key.h"
#include "util_tlv.h"

#include "key.h"
#include "keymgr.h"

#define KEY_JSON_OBJECT_STRING_MAX_LEN 10

/**
 * set_gen_opt_params() - Set key generation optional parameters.
 * @subtest: Subtest data
 * @args: Pointer to smw generate key args structure to update.
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_RESULT              - Function from SMW API returned a bad result.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -FAILED                  - Error in definition file
 * -API_STATUS_NOK          - SMW API Call return error
 */
static int set_gen_opt_params(struct subtest_data *subtest,
			      struct smw_generate_key_args *args,
			      struct keypair_ops *key_test)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *okey_params = NULL;
	struct smw_key_descriptor *desc = NULL;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;
	unsigned char **attrs = NULL;
	unsigned int *attrs_len = NULL;

	if (!subtest || !args || !key_test || !key_test->keys)
		return res;

	res = util_key_get_key_params(subtest, KEY_NAME_OBJ, &okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	attrs = (unsigned char **)&args->key_attributes_list;
	attrs_len = &args->key_attributes_list_length;

	/* Get the key policy */
	res = util_tlv_read_key_policy(attrs, attrs_len, okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs(attrs, attrs_len, okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	/*
	 * If 'pub_key' optional parameter is set, it defines
	 * the public key length in byte. If the length is 1,
	 * retrieve the public key length by calling SMW.
	 * Else if 'pub_key' not set, public key length is not set and
	 * there is not public key to export.
	 */
	desc = args->key_descriptor;

	if (key_is_public_len_set(key_test)) {
		public_length = *key_public_length(key_test);
		if (public_length == 1) {
			subtest->smw_status = smw_get_key_buffers_lengths(desc);
			if (subtest->smw_status != SMW_STATUS_OK) {
				DBG_PRINT("Error public key buffer len");
				return ERR_CODE(API_STATUS_NOK);
			}
		}

		*key_public_data(key_test) = malloc(public_length);

		if (!*key_public_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	/*
	 * If 'modulus' optional parameter is set, it defines the RSA modulus
	 * length in bytes.
	 * If the length is 1, retrieve the modulus length by calling SMW.
	 * Else if 'modulus' not set, modulus length is not set and there is
	 * no modulus to export.
	 */
	if (key_is_modulus(key_test)) {
		modulus_length = *key_modulus_length(key_test);
		if (modulus_length == 1) {
			subtest->smw_status = smw_get_key_buffers_lengths(desc);
			if (subtest->smw_status != SMW_STATUS_OK) {
				DBG_PRINT("Error modulus buffer len");
				return ERR_CODE(API_STATUS_NOK);
			}
		}

		*key_modulus(key_test) = malloc(modulus_length);

		if (!*key_modulus(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (!key_is_private_len_set(key_test) && !public_length &&
	    !modulus_length) {
		/* Remove key buffer if no private buffer set */
		desc->buffer = NULL;
	}

	return ERR_CODE(PASSED);
}

/**
 * set_import_opt_params() - Set key import optional parameters.
 * @subtest: Subtest data
 * @args: Pointer to smw import key args structure to update.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -FAILED                  - Error in definition file
 */
static int set_import_opt_params(struct subtest_data *subtest,
				 struct smw_import_key_args *args)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *okey_params = NULL;
	unsigned char **attrs = NULL;
	unsigned int *attrs_len = NULL;

	if (!subtest || !args)
		return res;

	res = util_key_get_key_params(subtest, KEY_NAME_OBJ, &okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	attrs = (unsigned char **)&args->key_attributes_list;
	attrs_len = &args->key_attributes_list_length;

	/* Get the key policy */
	res = util_tlv_read_key_policy(attrs, attrs_len, okey_params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs(attrs, attrs_len, okey_params);

	return res;
}

/**
 * set_export_opt_params() - Set key export optional parameters.
 * @subtest: Subtest data
 * @args: Pointer to smw export key args structure to update.
 * @key_test: Test exported keypair structure with operations
 * @exp_key_test: Test expected exported keypair structure with operations
 * @export_type: Type of key to export (private, public. keypair).
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_RESULT              - Function from SMW API returned a bad result.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * -FAILED                  - Error in definition file
 * -API_STATUS_NOK          - SMW API Call return error
 */
static int set_export_opt_params(struct subtest_data *subtest,
				 struct smw_export_key_args *args,
				 struct keypair_ops *key_test,
				 struct keypair_ops *exp_key_test,
				 enum export_type export_type)
{
	int res = ERR_CODE(PASSED);
	struct smw_key_descriptor tmp_key_desc = { 0 };

	if (!subtest || !args || !key_test || !exp_key_test)
		return ERR_CODE(BAD_ARGS);

	if (!args->key_descriptor->id)
		return ERR_CODE(PASSED);

	/*
	 * Prepare key buffers to get the exported keys.
	 * Get key buffers size exportable from SMW and
	 * then allocate only key buffer requested.
	 */
	key_test->keys->format_name = exp_key_test->keys->format_name;

	/*
	 * Get the key buffer length from the SMW library.
	 * Use a temporary key descriptor to not overwrite the
	 * test definition read value.
	 */
	tmp_key_desc.id = args->key_descriptor->id;
	tmp_key_desc.buffer = args->key_descriptor->buffer;

	subtest->smw_status = smw_get_security_size(&tmp_key_desc);
	if (subtest->smw_status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get security size returned %d",
			  subtest->smw_status);
		return ERR_CODE(API_STATUS_NOK);
	}

	subtest->smw_status = smw_get_key_type_name(&tmp_key_desc);
	if (subtest->smw_status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get key type name returned %d",
			  subtest->smw_status);
		return ERR_CODE(API_STATUS_NOK);
	}

	subtest->smw_status = smw_get_key_buffers_lengths(&tmp_key_desc);
	if (subtest->smw_status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get key buffers lengths returned %d",
			  subtest->smw_status);
		return ERR_CODE(API_STATUS_NOK);
	}

	/* Reset the key buffer length not query */
	switch (export_type) {
	case EXP_PRIV:
		*key_public_length(key_test) = 0;
		*key_public_data(key_test) = NULL;
		break;

	case EXP_PUB:
		*key_private_length(key_test) = 0;
		*key_private_data(key_test) = NULL;
		break;

	default:
		break;
	}

	/*
	 * Input key_desc is setup for key's id buffer length.
	 * If exp_key_test defines other key's buffer length, overwrites
	 * key_desc length regardless the export key type.
	 */
	if (*key_private_length(exp_key_test))
		*key_private_length(key_test) =
			*key_private_length(exp_key_test);

	if (*key_public_length(exp_key_test))
		*key_public_length(key_test) = *key_public_length(exp_key_test);

	if (!strcmp(tmp_key_desc.type_name, RSA_KEY) &&
	    *key_modulus_length(exp_key_test)) {
		*key_modulus_length(key_test) =
			*key_modulus_length(exp_key_test);
	}

	/* Allocate buffers function of the requested key */
	if (*key_private_length(key_test)) {
		*key_private_data(key_test) =
			malloc(*key_private_length(key_test));
		if (!*key_private_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (*key_public_length(key_test)) {
		*key_public_data(key_test) =
			malloc(*key_public_length(key_test));
		if (!*key_public_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (!strcmp(tmp_key_desc.type_name, RSA_KEY) &&
	    *key_modulus_length(key_test)) {
		*key_modulus(key_test) = malloc(*key_modulus_length(key_test));
		if (!*key_modulus(key_test)) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	return res;
}

/**
 * set_common_bad_args() - Common function handling bad test cases
 * @params: json-c object
 * @args: Pointer to smw operation key args structure.
 * @key: Pointer to the smw key descriptor
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * -ERROR_NOT_DEFINED           - Test error not defined.
 */
static int set_common_bad_args(json_object *params, void **args,
			       struct smw_key_descriptor **key)
{
	int ret = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!params)
		return ret;

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		/* 'test_error' not defined */
		ret = ERR_CODE(ERROR_NOT_DEFINED);
		break;

	case ARGS_NULL:
		*args = NULL;
		break;

	case KEY_DESC_NULL:
		/* Key descriptor is NULL */
		*key = NULL;
		break;

	case KEY_BUFFER_NULL:
		/* Key buffer is NULL */
		(*key)->buffer = NULL;
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}

/**
 * set_gen_bad_args() - Set generate key parameters for specific test cases.
 * @params: json-c parameters
 * @args: Pointer to smw generate key args structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * generation.
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_gen_bad_args(json_object *params,
			    struct smw_generate_key_args **args)
{
	int ret = ERR_CODE(BAD_ARGS);

	if (!args || !*args || !(*args)->key_descriptor) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = set_common_bad_args(params, (void **)args,
				  &(*args)->key_descriptor);
	if (ret == ERR_CODE(ERROR_NOT_DEFINED))
		ret = ERR_CODE(PASSED);

	return ret;
}

/**
 * set_del_bad_args() - Set delete key parameters for specific test cases.
 * @params: json-c parameters
 * @args: Pointer to smw delete key args structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * deletion.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_ARGS		- One of the arguments is bad.
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 */
static int set_del_bad_args(json_object *params,
			    struct smw_delete_key_args **args)
{
	int ret = ERR_CODE(BAD_ARGS);

	if (!args || !*args || !(*args)->key_descriptor ||
	    (*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = set_common_bad_args(params, (void **)args,
				  &(*args)->key_descriptor);
	if (ret == ERR_CODE(ERROR_NOT_DEFINED))
		ret = ERR_CODE(PASSED);

	return ret;
}

/**
 * set_import_bad_args() - Set import key parameters for specific test cases.
 * @params: json-c parameters
 * @args: Pointer to smw import key args structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * import.
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_import_bad_args(json_object *params,
			       struct smw_import_key_args **args)
{
	int ret = ERR_CODE(BAD_ARGS);

	if (!args || !*args || !(*args)->key_descriptor ||
	    !(*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = set_common_bad_args(params, (void **)args,
				  &(*args)->key_descriptor);
	if (ret == ERR_CODE(ERROR_NOT_DEFINED))
		ret = ERR_CODE(PASSED);

	return ret;
}

/**
 * set_export_bad_args() - Set export key parameters for specific test cases.
 * @subtest: Subtest data
 * @args: Pointer to smw export key args buffer structure.
 * @exp_key: Pointer to expected key buffer defined in test definition file.
 * @is_api_test: Test concerns the API validation.
 *
 * These configurations represent specific error case using SMW API for a key
 * export.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
static int set_export_bad_args(struct subtest_data *subtest,
			       struct smw_export_key_args **args,
			       struct smw_keypair_buffer *exp_key)
{
	int ret = ERR_CODE(BAD_ARGS);

	if (!args || !*args || !(*args)->key_descriptor ||
	    !(*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = set_common_bad_args(subtest->params, (void **)args,
				  &(*args)->key_descriptor);

	if (ret == ERR_CODE(ERROR_NOT_DEFINED)) {
		/*
		 * Test error code is not defined, if it's a test
		 * concerning the export API, the exported key buffer
		 * argument is defined by the parameters
		 * 'pub_key' and 'priv_key' in the test definition file.
		 */
		if (is_api_test(subtest))
			(*args)->key_descriptor->buffer = exp_key;

		ret = ERR_CODE(PASSED);
	}

	return ret;
}

/**
 * set_commit_bad_args() - Set commit key storage parameters for specific
 *                         test cases.
 * @params: json-c parameters
 * @args: Pointer to smw commit key storage args structure.
 *
 * These configurations represent specific error case using SMW API for a
 * commit key storage.
 *
 * Return:
 * PASSED			- Success.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_commit_bad_args(json_object *params,
			       struct smw_commit_key_storage_args **args)
{
	int ret = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!params || !args || !*args) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		/* 'test_error' not defined */
		ret = ERR_CODE(PASSED);
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

/**
 * compare_keys() - Compare SMW keys with expected keys
 * @key_test: Test exported keypair structure with operations
 * @exp_key_test: Test expected exported keypair structure with operations
 *
 * Function compares private key if expected key private data set.
 * Same if expected key public data set, compare public key.
 *
 * Return:
 * PASSED      - Success.
 * -SUBSYSTEM  - One of the keys is not correct
 */
static int compare_keys(struct keypair_ops *key_test,
			struct keypair_ops *exp_key_test)
{
	int res = ERR_CODE(PASSED);
	int tmp_res = ERR_CODE(PASSED);

	/*
	 * If test is to compare exported key with
	 * the one set in the test definition, do
	 * the comparaison.
	 */
	if (*key_private_length(exp_key_test))
		res = util_compare_buffers(*key_private_data(key_test),
					   *key_private_length(key_test),
					   *key_private_data(exp_key_test),
					   *key_private_length(exp_key_test));

	if (*key_public_length(exp_key_test))
		tmp_res =
			util_compare_buffers(*key_public_data(key_test),
					     *key_public_length(key_test),
					     *key_public_data(exp_key_test),
					     *key_public_length(exp_key_test));

	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	if (exp_key_test->modulus_length && *key_modulus_length(exp_key_test))
		tmp_res =
			util_compare_buffers(*key_modulus(key_test),
					     *key_modulus_length(key_test),
					     *key_modulus(exp_key_test),
					     *key_modulus_length(exp_key_test));
	if (res == ERR_CODE(PASSED))
		res = tmp_res;

	return res;
}

int generate_key(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	struct key_data key_data = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_generate_key_args args = { 0 };
	struct smw_generate_key_args *smw_gen_args = &args;
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Initialize key descriptor */
	res = key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Security size is mandatory */
	if (!key_is_security_set(&key_test)) {
		DBG_PRINT_MISS_PARAM("security_size");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Set optional parameters */
	res = set_gen_opt_params(subtest, smw_gen_args, &key_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_gen_bad_args(subtest->params, &smw_gen_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call generate key function and compare result with expected one */
	subtest->smw_status = smw_generate_key(smw_gen_args);
	if (subtest->smw_status == SMW_STATUS_OK ||
	    subtest->smw_status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		key_prepare_key_data(&key_test, &key_data);
		res = util_key_update_node(list_keys(subtest), key_name,
					   &key_data);
	} else {
		res = ERR_CODE(API_STATUS_NOK);
	}

exit:
	key_free_key(&key_test);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}

int delete_key(struct subtest_data *subtest)
{
	int res = ERR_CODE(FAILED);
	struct keypair_ops key_test = { 0 };
	struct smw_delete_key_args args = { 0 };
	struct smw_delete_key_args *smw_del_args = &args;
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.key_descriptor = &key_test.desc;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Initialize key descriptor, no key buffer */
	res = key_desc_init(&key_test, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Specific test cases */
	res = set_del_bad_args(subtest->params, &smw_del_args);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Call delete key function and compare result with expected one */
	subtest->smw_status = smw_delete_key(smw_del_args);
	if (subtest->smw_status != SMW_STATUS_OK)
		return ERR_CODE(API_STATUS_NOK);

	/*
	 * Key node is freed when the list is freed (at the of the test).
	 * Even if the key is deleted by the subsystem a test scenario
	 * can try to delete/use it after this operation.
	 */

	return ERR_CODE(PASSED);
}

int import_key(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	struct key_data key_data = { 0 };
	struct smw_keypair_buffer key_buffer;
	struct smw_import_key_args args = { 0 };
	struct smw_import_key_args *smw_import_args = &args;
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Initialize key descriptor */
	res = key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Security size is mandatory */
	if (!key_is_security_set(&key_test)) {
		DBG_PRINT_MISS_PARAM("security_size");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	res = set_import_opt_params(subtest, smw_import_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_import_bad_args(subtest->params, &smw_import_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call import key function and compare result with expected one */
	subtest->smw_status = smw_import_key(smw_import_args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	key_prepare_key_data(&key_test, &key_data);
	res = util_key_update_node(list_keys(subtest), key_name, &key_data);

exit:
	key_free_key(&key_test);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}

int export_key(struct subtest_data *subtest, enum export_type export_type)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test = { 0 };
	struct keypair_ops exp_key_test = { 0 };
	struct smw_export_key_args args = { 0 };
	struct smw_export_key_args *smw_export_args = &args;
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_keypair_buffer exp_key_buffer = { 0 };
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.key_descriptor = &key_test.desc;

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
	res = key_desc_init(&exp_key_test, &exp_key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &exp_key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Initialize exported keys operation argument.
	 * Don't set the buffer now to not read the
	 * defined public/private key if set in the
	 * test definition file.
	 */
	res = key_desc_init(&key_test, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_test, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Set the empty key buffer to get exported key and do key allocation
	 * function of the exported key query.
	 */
	res = key_desc_set_key(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = set_export_opt_params(subtest, &args, &key_test, &exp_key_test,
				    export_type);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_export_bad_args(subtest, &smw_export_args, &exp_key_buffer);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call export key function and compare result with expected one */
	subtest->smw_status = smw_export_key(smw_export_args);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

	if (subtest->smw_status == SMW_STATUS_OK)
		res = compare_keys(&key_test, &exp_key_test);

exit:
	key_free_key(&key_test);
	key_free_key(&exp_key_test);

	return res;
}

int get_key_attributes(struct subtest_data *subtest)
{
	int res = ERR_CODE(FAILED);
	int error = 0;
	struct keypair_ops key_test = { 0 };
	struct keypair_ops key_ref = { 0 };
	struct smw_get_key_attributes_args args = { 0 };
	const char *key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	args.key_descriptor = &key_test.desc;

	/* Key name is mandatory */
	res = util_read_json_type(&key_name, KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Initialize key descriptor, no key buffer */
	res = key_desc_init(&key_test, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	res = key_desc_init(&key_ref, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = key_read_descriptor(list_keys(subtest), &key_ref, key_name);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Set only the key identifier */
	key_test.desc.id = key_ref.desc.id;

	subtest->smw_status = smw_get_key_attributes(&args);
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	/*
	 * Validate the key attributes
	 */
	if (key_test.desc.security_size != key_ref.desc.security_size) {
		DBG_PRINT("Invalid security size got %u expected %u",
			  key_test.desc.security_size,
			  key_ref.desc.security_size);
		error++;
	}

	if (strcmp(key_test.desc.type_name, key_ref.desc.type_name)) {
		DBG_PRINT("Invalid key type got %s expected %s",
			  key_test.desc.type_name, key_ref.desc.type_name);
		error++;
	}

	if (error) {
		res = ERR_CODE(FAILED);
		goto exit;
	}

	res = util_tlv_check_key_policy(subtest, args.policy_list,
					args.policy_list_length);

	if (res == ERR_CODE(PASSED))
		res = util_tlv_check_lifecycle(args.lifecycle_list,
					       args.lifecycle_list_length);

exit:
	if (args.policy_list)
		free(args.policy_list);

	if (args.lifecycle_list)
		free(args.lifecycle_list);

	key_free_key(&key_test);

	return res;
}

int commit_key_storage(struct subtest_data *subtest)
{
	int res = ERR_CODE(FAILED);
	struct smw_commit_key_storage_args args = { 0 };
	struct smw_commit_key_storage_args *smw_args = &args;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = set_commit_bad_args(subtest->params, &smw_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	subtest->smw_status = smw_commit_key_storage(smw_args);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	return res;
}
