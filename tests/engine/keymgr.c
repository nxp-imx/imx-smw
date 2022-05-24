// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <smw_keymgr.h>

#include "keymgr.h"
#include "util.h"
#include "util_key.h"
#include "util_tlv.h"

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
	int res;
	struct smw_key_descriptor *desc;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	if (!subtest || !args || !key_test || !key_test->keys)
		return ERR_CODE(BAD_ARGS);

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args->key_attributes_list,
				  &args->key_attributes_list_length,
				  subtest->params);
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
	if (util_key_is_modulus(key_test)) {
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

	if (!util_key_is_private_len_set(key_test) && !public_length &&
	    !modulus_length) {
		/* Remove key buffer if no private buffer set */
		desc->buffer = NULL;
	}

	return ERR_CODE(PASSED);
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
		(*key)->id = 1;
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
	int ret;

	if (!args || !*args || !(*args)->key_descriptor) {
		DBG_PRINT_BAD_ARGS();
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
		DBG_PRINT_BAD_ARGS();
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
		DBG_PRINT_BAD_ARGS();
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
	int ret;

	if (!args || !*args || !(*args)->key_descriptor ||
	    !(*args)->key_descriptor->buffer) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
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

/**
 * save_key_ids_to_json_file() - Save key ids from a linked list in a json file.
 * @key_list: Key identifier linked list.
 * @filepath: Path of the json file.
 *
 * Return:
 * PASSED	- Success.
 * -BAD_ARGS	- One of the arguments is bad.
 * -INTERNAL	- Internal function failure.
 * Error code from check_file_extension().
 */
static int save_key_ids_to_json_file(struct llist *key_list, char *filepath)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int counter = 1;
	char key_object_string[KEY_JSON_OBJECT_STRING_MAX_LEN];
	void *node = NULL;
	unsigned int id;
	struct key_identifier_data *data = NULL;
	struct json_object *global_obj = NULL;
	struct json_object *id_obj = NULL;
	struct json_object *key_identifier_obj = NULL;
	struct json_object *key_obj = NULL;
	FILE *json_file = NULL;
	int nb_char;

	if (!key_list || !filepath) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = check_file_extension(filepath, DEFINITION_FILE_EXTENSION);
	if (res != ERR_CODE(PASSED))
		return res;

	json_file = fopen(filepath, "w+");
	if (!json_file) {
		DBG_PRINT("fopen failed, file is %s", filepath);
		return ERR_CODE(INTERNAL);
	}

	global_obj = json_object_new_object();
	if (!global_obj) {
		DBG_PRINT("Can't create a new json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	id_obj = json_object_new_int(0);
	if (!id_obj) {
		DBG_PRINT("Can't create a new json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	/* Add id_obj to global_obj */
	if (json_object_object_add(global_obj, "id", id_obj)) {
		DBG_PRINT("Can't add a json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	key_identifier_obj = json_object_new_int64(0);
	if (!key_identifier_obj) {
		DBG_PRINT("Can't create a new json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	/* Add key_identifier_obj to global_obj */
	if (json_object_object_add(global_obj, "key_identifier",
				   key_identifier_obj)) {
		DBG_PRINT("Can't add a json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	key_obj = json_object_new_string(key_object_string);
	if (!key_obj) {
		DBG_PRINT("Can't create a new json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	nb_char = fprintf(json_file, "{\n");
	if (nb_char < 0)
		DBG_PRINT("error %s", util_get_strerr());

	node = util_list_next(key_list, node, &id);

	while (node) {
		data = util_list_data(node);
		if (!data) {
			DBG_PRINT("Can't get the key identifier data");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		if (counter > 1) {
			nb_char = fprintf(json_file, ",\n");
			if (nb_char < 0)
				DBG_PRINT("error %s", util_get_strerr());
		}

		if (!json_object_set_int(id_obj, id)) {
			DBG_PRINT("json_object_set_int() failed");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		if (!json_object_set_int(key_identifier_obj,
					 data->key_identifier)) {
			DBG_PRINT("json_object_set_int64() failed");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		if (sprintf(key_object_string, "key %d", counter++) < 0) {
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		if (!json_object_set_string(key_obj, key_object_string)) {
			DBG_PRINT("json_object_set_string() failed");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		/*
		 * Fill json file with the following template:
		 * "key X":{ "id": XX, "key_identifier": XX}
		 */
		nb_char = fprintf(json_file, "%s:%s",
				  json_object_to_json_string(key_obj),
				  json_object_to_json_string(global_obj));
		if (nb_char < 0)
			DBG_PRINT("error %s", util_get_strerr());

		node = util_list_next(key_list, node, &id);
	}

	nb_char = fprintf(json_file, "\n}");
	if (nb_char < 0)
		DBG_PRINT("error %s", util_get_strerr());

exit:
	if (fclose(json_file))
		res = ERR_CODE(INTERNAL);

	/* Free json objects */
	if (global_obj)
		json_object_put(global_obj);

	if (key_obj)
		json_object_put(key_obj);

	return res;
}

/**
 * restore_key_ids_from_json_file() - Restore key ids from a json file to a key
 *                                    identifier linked list.
 * @subtest: Subtest data
 * @filepath: Path of the file.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARGS               - One of the arguments is bad.
 * -MISSING_PARAMS         - Missing mandatory parameters in @filepath.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -API_STATUS_NOK         - SMW API Call return error
 * Error code from file_to_json_object().
 */
static int restore_key_ids_from_json_file(struct subtest_data *subtest,
					  char *filepath)
{
	int res = ERR_CODE(FAILED);
	int id = 0;
	json_object *restore_obj = NULL;
	struct json_object_iter iter = { 0 };
	struct keypair_ops key = { 0 };

	if (!subtest || !filepath) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = check_file_extension(filepath, DEFINITION_FILE_EXTENSION);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_read_json_file(NULL, filepath, &restore_obj);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!restore_obj || !json_object_get_object(restore_obj))
		return ERR_CODE(INTERNAL);

	json_object_object_foreachC(restore_obj, iter)
	{
		res = util_read_json_type(&id, "id", t_int, iter.val);
		if (res != ERR_CODE(PASSED))
			break;

		res = util_read_json_type(&key.desc.id, "key_identifier", t_int,
					  iter.val);
		if (res != ERR_CODE(PASSED))
			break;

		subtest->smw_status = smw_get_security_size(&key.desc);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
			break;
		}

		res = util_key_add_node(list_keys(subtest), id, &key);
		if (res != ERR_CODE(PASSED))
			break;
	}

	json_object_put(restore_obj);

	return res;
}

int generate_key(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	struct smw_generate_key_args args = { 0 };
	struct smw_generate_key_args *smw_gen_args = &args;
	int key_id = INT_MAX;

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

	/* Initialize key descriptor */
	res = util_key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM("key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Security size is mandatory */
	if (!util_key_is_security_set(&key_test)) {
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
	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_key_add_node(list_keys(subtest), key_id, &key_test);

exit:
	util_key_free_key(&key_test);

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
	int key_id = INT_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.key_descriptor = &key_test.desc;

	/* Initialize key descriptor, no key buffer */
	res = util_key_desc_init(&key_test, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM("key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* Fill key descriptor field saved */
	res = util_key_find_key_node(list_keys(subtest), key_id, &key_test);
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
	 * Key node of the key identifiers linked is freed when the list is
	 * freed (at the of the test). Even if the key is deleted by the
	 * subsystem a test scenario can try to delete/use it after this
	 * operation.
	 */

	return ERR_CODE(PASSED);
}

int import_key(struct subtest_data *subtest)
{
	int res = ERR_CODE(PASSED);
	struct keypair_ops key_test;
	struct smw_keypair_buffer key_buffer;
	struct smw_import_key_args args = { 0 };
	struct smw_import_key_args *smw_import_args = &args;
	int key_id = INT_MAX;

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

	/* Initialize key descriptor */
	res = util_key_desc_init(&key_test, &key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM("key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Security size is mandatory */
	if (!util_key_is_security_set(&key_test)) {
		DBG_PRINT_MISS_PARAM("security_size");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs((unsigned char **)&args.key_attributes_list,
				  &args.key_attributes_list_length,
				  subtest->params);
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

	res = util_key_add_node(list_keys(subtest), key_id, &key_test);

exit:
	util_key_free_key(&key_test);

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
	int key_id = INT_MAX;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	args.version = subtest->version;
	args.key_descriptor = &key_test.desc;

	/*
	 * Initialize 2 key descriptors:
	 *  - one with the expected key buffers if private/public keys
	 *    are defined in the test definition file.
	 *  - one use for the export key operation.
	 */
	/* Initialize expected keys */
	res = util_key_desc_init(&exp_key_test, &exp_key_buffer);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&exp_key_test, &key_id, 0,
				       subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Initialize exported keys operation argument.
	 * Don't set the buffer now to not read the
	 * defined public/private key if set in the
	 * test definition file.
	 */
	res = util_key_desc_init(&key_test, NULL);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Read the json-c key description */
	res = util_key_read_descriptor(&key_test, &key_id, 0, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Key ID is mandatory */
	if (key_id == INT_MAX) {
		DBG_PRINT_MISS_PARAM("key_id");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	res = util_key_find_key_node(list_keys(subtest), key_id, &key_test);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* If Security size not set get it from the SMW key identifier */
	if (!util_key_is_security_set(&key_test)) {
		subtest->smw_status = smw_get_security_size(&key_test.desc);
		if (subtest->smw_status != SMW_STATUS_OK) {
			res = ERR_CODE(API_STATUS_NOK);
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
	util_key_free_key(&key_test);
	util_key_free_key(&exp_key_test);

	return res;
}

int save_key_ids_to_file(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	char *filename = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* 'filepath' is a mandatory parameter */
	res = util_read_json_type(&filename, FILEPATH_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	return save_key_ids_to_json_file(list_keys(subtest), filename);
}

int restore_key_ids_from_file(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	char *filename = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	/* 'filepath' is a mandatory parameter */
	res = util_read_json_type(&filename, FILEPATH_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	return restore_key_ids_from_json_file(subtest, filename);
}
