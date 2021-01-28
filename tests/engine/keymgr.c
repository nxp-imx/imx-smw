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
			      struct smw_generate_key_args *args)
{
	int res;
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keypair_buffer *key;

	if (!params || !args || !args->key_descriptor ||
	    !args->key_descriptor->buffer)
		return ERR_CODE(BAD_ARGS);

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args->key_attributes_list,
				  &args->key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		return res;

	key = args->key_descriptor->buffer;

	/*
	 * If 'pub_key' optional parameter is set, it defines
	 * the public key length in byte. If the length is 1,
	 * retreive the public key length by calling SMW.
	 * Else if 'pub_key' not set, public key length is not set and
	 * there is not public key to export.
	 */
	if (util_key_is_public_len_set(key)) {
		if (key->public_length == 1) {
			status = smw_get_key_buffers_lengths(
				args->key_descriptor);
			if (status != SMW_STATUS_OK) {
				DBG_PRINT(
					"Failed to get public key buffer len");
				return ERR_CODE(BAD_RESULT);
			}
		}

		key->public_data = malloc(key->public_length);

		if (!key->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	return ERR_CODE(PASSED);
}

/**
 * set_export_opt_params() - Set key export optional parameters.
 * @params: Pointer to json parameters.
 * @args: Pointer to smw export key args structure to update.
 * @exp_key_buffer: Pointer to expected exported keys (defined in test file).
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
				 struct smw_keypair_buffer *exp_key_buffer,
				 enum export_type export_type)
{
	int res = ERR_CODE(PASSED);
	int status;
	struct smw_key_descriptor tmp_key_desc = { 0 };
	struct smw_keypair_buffer *key_buffer;

	if (!params || !args || !exp_key_buffer || !args->key_descriptor ||
	    !args->key_descriptor->buffer)
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
	key_buffer = args->key_descriptor->buffer;
	key_buffer->format_name = exp_key_buffer->format_name;

	/*
	 * Get the key buffer length from the SMW library.
	 * Use a temporary key descriptor to not overwrite the
	 * test definition read value.
	 */
	tmp_key_desc.id = args->key_descriptor->id;
	tmp_key_desc.security_size = args->key_descriptor->security_size;
	tmp_key_desc.buffer = key_buffer;

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
		if (exp_key_buffer->private_length &&
		    !key_buffer->private_length)
			key_buffer->private_length =
				exp_key_buffer->private_length;

		if (export_type == EXP_PRIV) {
			key_buffer->public_length = 0;
			key_buffer->public_data = NULL;
		}
		break;

	case EXP_PUB:
		key_buffer->private_length = 0;
		key_buffer->private_data = NULL;
		break;

	default:
		break;
	}

	/* Alllocate buffers function of the requested key */
	if (key_buffer->private_length) {
		key_buffer->private_data = malloc(key_buffer->private_length);
		if (!key_buffer->private_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	if (key_buffer->public_length) {
		key_buffer->public_data = malloc(key_buffer->public_length);
		if (!key_buffer->public_data) {
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
	struct smw_keypair_buffer *key_buffer;
	enum arguments_test_err_case error;

	if (!params)
		return ERR_CODE(BAD_ARGS);

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	key_buffer = (*key)->buffer;

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
		key_buffer->format_name = KEY_FORMAT_UNDEFINED;
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
 * @key_buffer: SMW keys buffer
 * @exp_key_buffer: Expected keys buffer
 *
 * Function compares private key if expected key private data set.
 * Same if expected key public data set, compare public key.
 *
 * Return:
 * PASSED      - Success.
 * -SUBSYSTEM  - One of the keys is not correct
 */
static int compare_keys(struct smw_keypair_buffer *key_buffer,
			struct smw_keypair_buffer *exp_key_buffer)
{
	int res = ERR_CODE(PASSED);

	/*
	 * If test is to compare exported key with
	 * the one set in the test definition, do
	 * the comparaison.
	 */
	if (exp_key_buffer->private_data) {
		if (exp_key_buffer->private_length !=
		    key_buffer->private_length) {
			DBG_PRINT("Bad Private length got %d expected %d",
				  key_buffer->private_length,
				  exp_key_buffer->private_length);
			res = ERR_CODE(SUBSYSTEM);
		} else if (memcmp(exp_key_buffer->private_data,
				  key_buffer->private_data,
				  key_buffer->private_length)) {
			DBG_DHEX("Got Private Key", key_buffer->private_data,
				 key_buffer->private_length);
			DBG_DHEX("Expected Private Key",
				 exp_key_buffer->private_data,
				 exp_key_buffer->private_length);
			res = ERR_CODE(SUBSYSTEM);
		}
	}

	if (exp_key_buffer->public_data) {
		if (exp_key_buffer->public_length !=
		    key_buffer->public_length) {
			DBG_PRINT("Bad Public length got %d expected %d",
				  key_buffer->public_length,
				  exp_key_buffer->public_length);
			res = ERR_CODE(SUBSYSTEM);
		} else if (memcmp(exp_key_buffer->public_data,
				  key_buffer->public_data,
				  key_buffer->public_length)) {
			DBG_DHEX("Got Public Key", key_buffer->public_data,
				 key_buffer->public_length);
			DBG_DHEX("Expected Public Key",
				 exp_key_buffer->public_data,
				 exp_key_buffer->public_length);
			res = ERR_CODE(SUBSYSTEM);
		}
	}

	return res;
}

int generate_key(json_object *params, struct common_parameters *common_params,
		 char *key_type, struct key_identifier_list **key_identifiers,
		 int *ret_status)
{
	int res = ERR_CODE(PASSED);
	struct smw_key_descriptor key_descriptor;
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

	args.key_descriptor = &key_descriptor;

	/* Initialize key descriptor */
	res = util_key_desc_init(&key_descriptor, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Setup the key type name */
	key_descriptor.type_name = key_type;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_descriptor, &key_id, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Security size is mandatory */
	if (!util_key_is_security_set(&key_descriptor)) {
		DBG_PRINT_MISS_PARAM(__func__, "security_size");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Set optional parameters */
	res = set_gen_opt_params(params, smw_gen_args);
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
		res = util_key_add_node(key_identifiers, key_id,
					args.key_descriptor);

exit:
	if (key_buffer.public_data)
		free(key_buffer.public_data);

	if (key_buffer.private_data)
		free(key_buffer.private_data);

	return res;
}

int delete_key(json_object *params, struct common_parameters *common_params,
	       struct key_identifier_list *key_identifiers, int *ret_status)
{
	int res = ERR_CODE(FAILED);
	struct smw_key_descriptor key_descriptor;
	struct smw_delete_key_args args = { 0 };
	struct smw_delete_key_args *smw_del_args = &args;
	int key_id = INT_MAX;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;
	args.key_descriptor = &key_descriptor;

	/* Initialize key descriptor, no key buffer */
	res = util_key_desc_init(&key_descriptor, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_descriptor, &key_id, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Fill key descriptor field saved */
	res = util_key_find_key_node(key_identifiers, key_id, &key_descriptor);
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
	struct smw_key_descriptor key_descriptor;
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

	args.key_descriptor = &key_descriptor;

	/* Initialize key descriptor */
	res = util_key_desc_init(&key_descriptor, &key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Setup the key type name */
	key_descriptor.type_name = key_type;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_descriptor, &key_id, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Security size is mandatory */
	if (!util_key_is_security_set(&key_descriptor)) {
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
		res = util_key_add_node(key_identifiers, key_id,
					args.key_descriptor);

exit:
	if (key_buffer.private_data)
		free(key_buffer.private_data);

	if (key_buffer.public_data)
		free(key_buffer.public_data);

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
	struct smw_export_key_args args = { 0 };
	struct smw_export_key_args *smw_export_args = &args;
	struct smw_key_descriptor key_descriptor;
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_keypair_buffer exp_key_buffer;
	int key_id = INT_MAX;

	if (!params || !common_params || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	args.version = common_params->version;
	args.key_descriptor = &key_descriptor;

	/*
	 * Initialize key descriptor with the expected key buffers
	 * if private/public keys are defined in the test definition
	 * file.
	 */
	res = util_key_desc_init(&key_descriptor, &exp_key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_descriptor, &key_id, params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	res = util_key_find_key_node(key_identifiers, key_id, &key_descriptor);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* If Security size not set get it from the SMW key identifier */
	if (!util_key_is_security_set(&key_descriptor)) {
		status = smw_get_security_size(&key_descriptor);
		if (status != SMW_STATUS_OK) {
			res = ERR_CODE(BAD_RESULT);
			goto exit;
		}
	}

	/*
	 * Keep expected key buffers for the end to do the comparaison
	 * with exported keys.
	 * Set the empty key buffer to get exported key and do key allocation
	 * function of the exported key query.
	 */
	key_descriptor.buffer = &key_buffer;
	res = set_export_opt_params(params, &args, &exp_key_buffer,
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
		res = compare_keys(&key_buffer, &exp_key_buffer);

exit:
	if (key_buffer.private_data)
		free(key_buffer.private_data);

	if (key_buffer.public_data)
		free(key_buffer.public_data);

	if (exp_key_buffer.private_data)
		free(exp_key_buffer.private_data);

	if (exp_key_buffer.public_data)
		free(exp_key_buffer.public_data);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}
