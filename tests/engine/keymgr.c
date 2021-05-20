// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_key.h"
#include "util_tlv.h"
#include "types.h"
#include "keymgr.h"

#include "smw_keymgr.h"
#include "smw_status.h"

/*
 * This identifier is used for test error tests.
 * It represents the following key:
 *  - Generated/Imported by subsystem ID 0
 *  - Type is NIST
 *  - Parity is Public
 *  - Security size is 192
 *  - Subsystem Key ID is 1
 */
#define FAKE_KEY_NIST_192_ID INT64_C(0x00C000000001)

/**
 * set_gen_opt_params() - Set key generation optional parameters.
 * @params: Pointer to json parameters.
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
 */
static int set_gen_opt_params(json_object *params,
			      struct smw_generate_key_args *args,
			      struct keypair_ops *key_test)
{
	int res;
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_key_descriptor *desc;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	if (!params || !args || !key_test || !key_test->keys)
		return ERR_CODE(BAD_ARGS);

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args->key_attributes_list,
				  &args->key_attributes_list_length, params);
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

	if (util_key_is_public_len_set(key_test)) {
		public_length = *key_public_length(key_test);
		if (public_length == 1) {
			status = smw_get_key_buffers_lengths(desc);
			if (status != SMW_STATUS_OK) {
				DBG_PRINT("Error public key buffer len");
				return ERR_CODE(BAD_RESULT);
			}
		}

		*key_public_data(key_test) = malloc(public_length);

		if (!*key_public_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
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
	if (util_key_is_modulus(key_test)) {
		modulus_length = *key_modulus_length(key_test);
		if (modulus_length == 1) {
			status = smw_get_key_buffers_lengths(desc);
			if (status != SMW_STATUS_OK) {
				DBG_PRINT("Error modulus buffer len");
				return ERR_CODE(BAD_RESULT);
			}
		}

		*key_modulus(key_test) = malloc(modulus_length);

		if (!*key_modulus(key_test)) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (!util_key_is_private_len_set(key_test) && !public_length &&
	    !modulus_length) {
		/* Remove key buffer if no private buffer set */
		desc->buffer = NULL;
	}

	return ERR_CODE(PASSED);
}

/**
 * set_export_opt_params() - Set key export optional parameters.
 * @params: Pointer to json parameters.
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
 */
static int set_export_opt_params(json_object *params,
				 struct smw_export_key_args *args,
				 struct keypair_ops *key_test,
				 struct keypair_ops *exp_key_test,
				 enum export_type export_type)
{
	int res = ERR_CODE(PASSED);
	int status;
	struct smw_key_descriptor tmp_key_desc = { 0 };

	if (!params || !args || !key_test || !exp_key_test)
		return ERR_CODE(BAD_ARGS);

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args->key_attributes_list,
				  &args->key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		return res;

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

	status = smw_get_security_size(&tmp_key_desc);
	if (status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get security size returned %d", status);
		return ERR_CODE(BAD_RESULT);
	}

	status = smw_get_key_type_name(&tmp_key_desc);
	if (status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get key type name returned %d", status);
		return ERR_CODE(BAD_RESULT);
	}

	status = smw_get_key_buffers_lengths(&tmp_key_desc);
	if (status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get key buffers lengths returned %d", status);
		return ERR_CODE(BAD_RESULT);
	}

	/* Reset the key buffer length not query */
	switch (export_type) {
	case EXP_KEYPAIR:
	case EXP_PRIV:
		/*
		 * In case the test ask for a private key but SMW returned
		 * a private key length of 0, force the private key length
		 * to be exported with expected private key length
		 */
		if (*key_private_length(exp_key_test) &&
		    !*key_private_length(key_test))
			*key_private_length(key_test) =
				*key_private_length(exp_key_test);

		if (export_type == EXP_PRIV) {
			*key_public_length(key_test) = 0;
			*key_public_data(key_test) = NULL;
		}
		break;

	case EXP_PUB:
		*key_private_length(key_test) = 0;
		*key_private_data(key_test) = NULL;
		break;

	default:
		break;
	}

	/* Allocate buffers function of the requested key */
	if (*key_private_length(key_test)) {
		*key_private_data(key_test) =
			malloc(*key_private_length(key_test));
		if (!*key_private_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (*key_public_length(key_test)) {
		*key_public_data(key_test) =
			malloc(*key_public_length(key_test));
		if (!*key_public_data(key_test)) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (!strcmp(tmp_key_desc.type_name, RSA_KEY) &&
	    *key_modulus_length(key_test)) {
		*key_modulus(key_test) = malloc(*key_modulus_length(key_test));
		if (!*key_modulus(key_test)) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
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
	int ret;
	enum arguments_test_err_case error;

	if (!params)
		return ERR_CODE(BAD_ARGS);

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

	case KEY_DESC_ID_SET:
		/* Key descriptor @id field is set */
		(*key)->id = FAKE_KEY_NIST_192_ID;
		break;

	case KEY_DESC_ID_NOT_SET:
		/* Key descriptor @id field is not set */
		(*key)->id = 0;
		break;

	case BAD_FORMAT:
		/* key format is undefined */
		if (!(*key)->buffer)
			ret = ERR_CODE(BAD_ARGS);
		else
			(*key)->buffer->format_name = KEY_FORMAT_UNDEFINED;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, "test_error");
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
	int ret;

	if (!args || !*args || !(*args)->key_descriptor) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
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
	int ret;

	if (!args || !*args || !(*args)->key_descriptor ||
	    (*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
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
	int ret;

	if (!args || !*args || !(*args)->key_descriptor ||
	    !(*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	ret = set_common_bad_args(params, (void **)args,
				  &(*args)->key_descriptor);
	if (ret == ERR_CODE(ERROR_NOT_DEFINED))
		ret = ERR_CODE(PASSED);

	return ret;
}

/**
 * set_export_bad_args() - Set export key parameters for specific test cases.
 * @params: json-c parameters
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
static int set_export_bad_args(json_object *params,
			       struct smw_export_key_args **args,
			       struct smw_keypair_buffer *exp_key,
			       int is_api_test)
{
	int ret;

	if (!args || !*args || !(*args)->key_descriptor ||
	    !(*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	ret = set_common_bad_args(params, (void **)args,
				  &(*args)->key_descriptor);

	if (ret == ERR_CODE(ERROR_NOT_DEFINED)) {
		/*
		 * Test error code is not defined, if it's a test
		 * concerning the export API, the exported key buffer
		 * argument is defined by the parameters
		 * 'pub_key' and 'priv_key' in the test definition file.
		 */
		if (is_api_test)
			(*args)->key_descriptor->buffer = exp_key;

		ret = ERR_CODE(PASSED);
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
		res = util_compare_buffers(*key_public_data(key_test),
					   *key_public_length(key_test),
					   *key_public_data(exp_key_test),
					   *key_public_length(exp_key_test));

	if (exp_key_test->modulus_length && *key_modulus_length(exp_key_test))
		res = util_compare_buffers(*key_modulus(key_test),
					   *key_modulus_length(key_test),
					   *key_modulus(exp_key_test),
					   *key_modulus_length(exp_key_test));

	return res;
}

int generate_key(json_object *params, struct common_parameters *common_params,
		 char *key_type, struct key_identifier_list **key_identifiers,
		 int *ret_status)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	struct smw_generate_key_args args = { 0 };
	struct smw_generate_key_args *smw_gen_args = &args;
	int key_id = INT_MAX;

	if (!params || !key_identifiers || !ret_status || !common_params) {
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
	res = util_key_desc_init(&key_test, &key_buffer, key_type);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Setup the key type name */
	key_test.desc.type_name = key_type;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Security size is mandatory */
	if (!util_key_is_security_set(&key_test)) {
		DBG_PRINT_MISS_PARAM(__func__, "security_size");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Set optional parameters */
	res = set_gen_opt_params(params, smw_gen_args, &key_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_gen_bad_args(params, &smw_gen_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call generate key function and compare result with expected one */
	*ret_status = smw_generate_key(smw_gen_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK)
		res = util_key_add_node(key_identifiers, key_id, &key_test);

exit:
	util_key_free_key(&key_test);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}

int delete_key(json_object *params, struct common_parameters *common_params,
	       struct key_identifier_list *key_identifiers, int *ret_status)
{
	int res = ERR_CODE(FAILED);
	struct keypair_ops key_test;
	struct smw_delete_key_args args = { 0 };
	struct smw_delete_key_args *smw_del_args = &args;
	int key_id = INT_MAX;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;
	args.key_descriptor = &key_test.desc;

	/* Initialize key descriptor, no key buffer */
	res = util_key_desc_init(&key_test, NULL, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Fill key descriptor field saved */
	res = util_key_find_key_node(key_identifiers, key_id, &key_test);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Specific test cases */
	res = set_del_bad_args(params, &smw_del_args);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Call delete key function and compare result with expected one */
	*ret_status = smw_delete_key(smw_del_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res))
		return ERR_CODE(BAD_RESULT);

	/*
	 * Key node of the key identifiers linked is freed when the list is
	 * freed (at the of the test). Even if the key is deleted by the
	 * subsystem a test scenario can try to delete/use it after this
	 * operation.
	 */

	return ERR_CODE(PASSED);
}

int import_key(json_object *params, struct common_parameters *common_params,
	       char *key_type, struct key_identifier_list **key_identifiers,
	       int *ret_status)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	struct smw_import_key_args args = { 0 };
	struct smw_import_key_args *smw_import_args = &args;
	int key_id = INT_MAX;

	if (!params || !common_params || !key_identifiers || !ret_status) {
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
	res = util_key_desc_init(&key_test, &key_buffer, key_type);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Setup the key type name */
	key_test.desc.type_name = key_type;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Security size is mandatory */
	if (!util_key_is_security_set(&key_test)) {
		DBG_PRINT_MISS_PARAM(__func__, "security_size");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args.key_attributes_list,
				  &args.key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_import_bad_args(params, &smw_import_args);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call import key function and compare result with expected one */
	*ret_status = smw_import_key(smw_import_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK)
		res = util_key_add_node(key_identifiers, key_id, &key_test);

exit:
	util_key_free_key(&key_test);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}

int export_key(json_object *params, struct common_parameters *common_params,
	       enum export_type export_type,
	       struct key_identifier_list *key_identifiers, int *ret_status)
{
	int res = ERR_CODE(PASSED);
	int status = SMW_STATUS_OPERATION_FAILURE;
	struct keypair_ops key_test;
	struct keypair_ops exp_key_test;
	struct smw_export_key_args args = { 0 };
	struct smw_export_key_args *smw_export_args = &args;
	struct smw_keypair_buffer key_buffer;
	struct smw_keypair_buffer exp_key_buffer;
	int key_id = INT_MAX;
	json_object *obj;
	char *key_type = NULL;

	if (!params || !common_params || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;
	args.key_descriptor = &key_test.desc;

	/*
	 * Note: For RSA, key type must be known before keypair ops init. If the
	 * "key_type" parameter is not correctly set, a seg fault will occurred
	 */
	if (json_object_object_get_ex(params, KEY_TYPE_OBJ, &obj))
		key_type = (char *)json_object_get_string(obj);

	/*
	 * Initialize 2 key descriptors:
	 *  - one with the expected key buffers if private/public keys
	 *    are defined in the test definition file.
	 *  - one use for the export key operation.
	 */
	/* Initialize expected keys */
	res = util_key_desc_init(&exp_key_test, &exp_key_buffer, key_type);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&exp_key_test, &key_id, 0, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Initialize exported keys operation argument.
	 * Don't set the buffer now to not read the
	 * defined public/private key if set in the
	 * test definition file.
	 */
	res = util_key_desc_init(&key_test, NULL, key_type);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	res = util_key_find_key_node(key_identifiers, key_id, &key_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* If Security size not set get it from the SMW key identifier */
	if (!util_key_is_security_set(&key_test)) {
		status = smw_get_security_size(&key_test.desc);
		if (status != SMW_STATUS_OK) {
			res = ERR_CODE(BAD_RESULT);
			goto exit;
		}
	}

	/*
	 * Set the empty key buffer to get exported key and do key allocation
	 * function of the exported key query.
	 */
	res = util_key_desc_set_key(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = set_export_opt_params(params, &args, &key_test, &exp_key_test,
				    export_type);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Specific test cases */
	res = set_export_bad_args(params, &smw_export_args, &exp_key_buffer,
				  common_params->is_api_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Call export key function and compare result with expected one */
	*ret_status = smw_export_key(smw_export_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK)
		res = compare_keys(&key_test, &exp_key_test);

exit:
	util_key_free_key(&key_test);
	util_key_free_key(&exp_key_test);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}
