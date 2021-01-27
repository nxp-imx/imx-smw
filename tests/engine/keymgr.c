// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_tlv.h"
#include "types.h"
#include "json_types.h"
#include "keymgr.h"
#include "smw_keymgr.h"
#include "smw_status.h"

/*
 * This identifier is used for export API tests.
 * It represents the following key:
 *  - Generated/Imported by subsystem ID 0
 *  - Type is NIST
 *  - Parity is Public
 *  - Security size is 192
 *  - Subsystem ID is 1
 */
#define TEST_ID 824633720833

/**
 * set_gen_opt_params() - Set key generation optional parameters.
 * @params: Pointer to json parameters.
 * @key_args: Pointer to smw generate key args structure to update.
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
			      struct smw_generate_key_args *key_args)
{
	int res;
	int status = SMW_STATUS_INVALID_PARAM;
	json_object *key_format = NULL;
	json_object *pub_key_obj = NULL;

	if (!params || !key_args)
		return ERR_CODE(BAD_ARGS);

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs(
		(unsigned char **)&key_args->key_attributes_list,
		&key_args->key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get 'format' optional parameter */
	if (json_object_object_get_ex(params, KEY_FORMAT_OBJ, &key_format))
		key_args->key_descriptor->buffer->format_name =
			json_object_get_string(key_format);

	/*
	 * Get 'pub_key' optional parameter.
	 * If set to 1: allocate a public key buffer.
	 * Else: wrong value.
	 */
	if (json_object_object_get_ex(params, PUB_KEY_OBJ, &pub_key_obj)) {
		if (json_object_get_int(pub_key_obj) != 1) {
			DBG_PRINT_BAD_PARAM(__func__, "pub_key");
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		status = smw_get_key_buffers_lengths(key_args->key_descriptor);
		if (status != SMW_STATUS_OK) {
			DBG_PRINT("Failed to get public key buffer len");
			return ERR_CODE(BAD_RESULT);
		}

		key_args->key_descriptor->buffer->public_data =
			malloc(key_args->key_descriptor->buffer->public_length);

		if (!key_args->key_descriptor->buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
	}

	return ERR_CODE(PASSED);
}

/**
 * set_gen_bad_args() - Set generate key parameters for specific test cases.
 * @error: Test error id.
 * @ptr: Pointer to smw generate key args structure.
 * @args: Pointer to smw generate key args buffer structure.
 * @key: Pointer to smw key descriptor structure.
 * @key_buffer: Pointer to smw keypair buffer structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * generation.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_gen_bad_args(enum arguments_test_err_case error,
			    struct smw_generate_key_args **ptr,
			    struct smw_generate_key_args *args,
			    struct smw_key_descriptor *key,
			    struct smw_keypair_buffer *key_buffer)
{
	if (!ptr || !args || !key || !key_buffer)
		return ERR_CODE(BAD_ARGS);

	if (error == KEY_DESC_NULL) {
		/* Key descriptor is NULL */
		args->key_descriptor = NULL;
		goto exit;
	}

	if (error == KEY_DESC_ID_SET) {
		/* Key descriptor @id field is set */
		key->id = 1;
	} else {
		if (error == PUB_KEY_BUFF_TOO_SMALL) {
			/* Public key buffer is too small */
			key_buffer->public_length = key->security_size / 8;
			key_buffer->public_data =
				malloc(key_buffer->public_length);

			if (!key_buffer->public_data) {
				DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
				return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			}
		} else if (error == PRIV_KEY_BUFF_SET ||
			   error == PRIV_KEY_BUFF_LEN_SET) {
			/* Private key buffer len is set */
			key_buffer->private_length = key->security_size / 8;

			/* Private buffer is set */
			if (error == PRIV_KEY_BUFF_SET) {
				key_buffer->private_data =
					malloc(key_buffer->private_length);

				if (!key_buffer->private_data) {
					DBG_PRINT_ALLOC_FAILURE(__func__,
								__LINE__);
					return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
				}
			}
		} else {
			DBG_PRINT_BAD_PARAM(__func__, "test_error");
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		key->buffer = key_buffer;
	}

	args->key_descriptor = key;

exit:
	*ptr = args;
	return ERR_CODE(PASSED);
}

/**
 * set_del_bad_args() - Set delete key parameters for specific test cases.
 * @error: Test error id.
 * @ptr: Pointer to smw delete key args structure.
 * @args: Pointer to smw delete key args buffer structure.
 * @key: Pointer to smw key descriptor structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * deletion.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_ARGS		- One of the arguments is bad.
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 */
static int set_del_bad_args(enum arguments_test_err_case error,
			    struct smw_delete_key_args **ptr,
			    struct smw_delete_key_args *args,
			    struct smw_key_descriptor *key)
{
	if (!args || !key || !ptr)
		return ERR_CODE(BAD_ARGS);

	switch (error) {
	case KEY_DESC_NULL:
		/* key descriptor is NULL */
		args->key_descriptor = NULL;
		goto exit;

	case KEY_TYPE_UNDEFINED:
		/*
		 * key descriptor type name field is set with undefined
		 * value
		 */
		key->type_name = "UNDEFINED";
		break;

	case BAD_KEY_SEC_SIZE:
		/*
		 * key descriptor security size field is set and doesn't
		 * match the one set in the key descriptor id field.
		 */
		key->security_size = 129;
		key->id = 1;
		break;

	case BAD_KEY_TYPE:
		/*
		 * key descriptor type name field is set and doesn't
		 * match the one set in the key descriptor id field.
		 * This case assume that AES key type name value is
		 * different from 0.
		 */
		key->type_name = "AES";
		key->id = 1;
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, "test_error");
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	args->key_descriptor = key;

exit:
	*ptr = args;
	return ERR_CODE(PASSED);
}

/**
 * set_import_opt_params() - Set key import optional parameters.
 * @params: Pointer to json parameters.
 * @key_args: Pointer to smw import key args structure to update.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
static int set_import_opt_params(json_object *params,
				 struct smw_import_key_args *key_args)
{
	int res = ERR_CODE(PASSED);
	struct smw_key_descriptor *key;
	struct smw_keypair_buffer *key_buffer;

	if (!params || !key_args || !key_args->key_descriptor) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	key = key_args->key_descriptor;
	key_buffer = key->buffer;
	if (!key_buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs(
		(unsigned char **)&key_args->key_attributes_list,
		&key_args->key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get the keys optional parameter */
	res = util_read_keys(key_buffer, params);

	return res;
}

/**
 * set_import_bad_args() - Set import key parameters for specific test cases.
 * @error: Test error id.
 * @ptr: Pointer to smw import key args structure.
 * @args: Pointer to smw import key args buffer structure.
 * @key: Pointer to smw key descriptor structure.
 * @key_buffer: Pointer to smw keypair buffer structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * import.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_import_bad_args(enum arguments_test_err_case error,
			       struct smw_import_key_args **ptr,
			       struct smw_import_key_args *args,
			       struct smw_key_descriptor *key,
			       struct smw_keypair_buffer *key_buffer)
{
	if (!ptr || !args || !key || !key_buffer)
		return ERR_CODE(BAD_ARGS);

	switch (error) {
	case KEY_DESC_NULL:
		/* Key descriptor is NULL */
		args->key_descriptor = NULL;
		break;

	case KEY_BUFFER_NULL:
		/* Nothing to do expect set args->key_descriptor */
		args->key_descriptor = key;
		break;

	case KEY_DESC_ID_SET:
		/* Key descriptor @id field is set */
		args->key_descriptor = key;
		key->id = 1;
		break;

	case PUB_DATA_LEN_NOT_SET:
		/* Buffer size doesn't matter */
		args->key_descriptor = key;
		key->buffer = key_buffer;
		key_buffer->public_data = malloc(key->security_size / 8);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		break;

	case PRIV_DATA_LEN_NOT_SET:
		/* Buffer size doesn't matter */
		args->key_descriptor = key;
		key->buffer = key_buffer;
		key_buffer->private_data = malloc(key->security_size / 8);

		if (!key_buffer->private_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, "test_error");
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	*ptr = args;
	return ERR_CODE(PASSED);
}

/**
 * set_export_opt_params() - Set key export optional parameters.
 * @params: Pointer to json parameters.
 * @key_args: Pointer to smw export key args structure to update.
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
				 struct smw_export_key_args *key_args,
				 struct smw_keypair_buffer *exp_key_buffer,
				 enum export_type export_type)
{
	int res = ERR_CODE(PASSED);
	int status;
	struct smw_keypair_buffer *key_buffer;

	if (!params || !key_args || !exp_key_buffer ||
	    !key_args->key_descriptor)
		return ERR_CODE(BAD_ARGS);

	/* Get 'attributes_list' optional parameter */
	res = util_tlv_read_attrs(
		(unsigned char **)&key_args->key_attributes_list,
		&key_args->key_attributes_list_length, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/* Get the expected keys parameter */
	res = util_read_keys(exp_key_buffer, params);
	if (res != ERR_CODE(PASSED))
		return res;

	/*
	 * Prepare key buffers to get the exported keys
	 * First read the expected key buffers length and then allocate
	 * buffers.
	 * Note that, only the public key can be exported, hence SMW
	 * must set only the public key buffer length.
	 */
	key_buffer = key_args->key_descriptor->buffer;
	key_buffer->format_name = exp_key_buffer->format_name;

	status = smw_get_key_buffers_lengths(key_args->key_descriptor);
	if (status != SMW_STATUS_OK) {
		DBG_PRINT("SMW Get key buffers lengths returned %d", status);
		return ERR_CODE(BAD_RESULT);
	}

	/* Check if private key buffer length is 0 */
	if (key_buffer->private_length != 0) {
		DBG_PRINT("Wrong SMW private key length expected 0 got %d",
			  key_buffer->private_length);
		return ERR_CODE(BAD_RESULT);
	}

	/* Alllocate buffers function of the requested key */
	switch (export_type) {
	case EXP_KEYPAIR:
		/*
		 * Private buffer size doesn't matter as private key
		 * export is not supported by any subsystem.
		 */
		key_buffer->private_length = 10;
		key_buffer->private_data = malloc(key_buffer->private_length);
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->private_data || !key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
		break;

	case EXP_PRIV:
		/*
		 * Private buffer size doesn't matter as private key
		 * export is not supported by any subsystem.
		 */
		key_buffer->private_length = 10;
		key_buffer->private_data = malloc(key_buffer->private_length);
		key_buffer->public_data = NULL;

		if (!key_buffer->private_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
		break;

	case EXP_PUB:
		key_buffer->public_data = malloc(key_buffer->public_length);
		key_buffer->private_data = NULL;

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
		break;

	default:
		res = ERR_CODE(BAD_PARAM_TYPE);
		break;
	}

	return res;
}

/**
 * set_export_bad_args() - Set export key parameters for specific test cases.
 * @error: Test error id.
 * @smw_export_args: Pointer to smw export key args buffer structure.
 *
 * These configurations represent specific error case using SMW API for a key
 * export.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
static int set_export_bad_args(enum arguments_test_err_case error,
			       struct smw_export_key_args **smw_export_args)
{
	struct smw_export_key_args *args = *smw_export_args;
	struct smw_key_descriptor *key;
	struct smw_keypair_buffer *key_buffer;

	if (!args || !args->key_descriptor) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	key = args->key_descriptor;
	key_buffer = key->buffer;
	if (!key_buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	switch (error) {
	case ARGS_NULL:
		*smw_export_args = NULL;
		break;

	case KEY_DESC_NULL:
		/* Key descriptor is NULL */
		args->key_descriptor = NULL;
		break;

	case KEY_DESC_ID_NOT_SET:
		key->id = 0;
		break;

	case KEY_BUFFER_NULL:
		key->id = TEST_ID;
		key->buffer = NULL;
		break;

	case NO_BUFFER_SET:
		key->id = TEST_ID;
		key_buffer->private_data = NULL;
		key_buffer->public_data = NULL;
		break;

	case PUB_DATA_LEN_NOT_SET:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->public_data = malloc(10);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		break;

	case PRIV_DATA_LEN_NOT_SET:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->private_data = malloc(10);

		if (!key_buffer->private_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		break;

	case BAD_FORMAT:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->public_length = 10;
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		key_buffer->format_name = "UNDEFINED";
		break;

	case WRONG_TYPE_NAME:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->public_length = 10;
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		key->type_name = "AES";
		break;

	case WRONG_SECURITY_SIZE:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->public_length = 10;
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		key->security_size = 128;
		break;

	case BAD_VERSION:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->public_length = 10;
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		args->version = '1';
		break;

	case BAD_ATTRIBUTES:
		key->id = TEST_ID;
		/* Buffer size doesn't matter */
		key_buffer->public_length = 10;
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		args->key_attributes_list_length = strlen("undefined");
		args->key_attributes_list =
			calloc(1, args->key_attributes_list_length + 1);
		if (!args->key_attributes_list) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
		sprintf((char *)args->key_attributes_list, "undefined");
		break;

	case PUB_KEY_BUFF_TOO_SMALL:
		key->id = TEST_ID;
		key_buffer->public_length = 10;
		key_buffer->public_data = malloc(key_buffer->public_length);

		if (!key_buffer->public_data) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, "test_error");
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	return ERR_CODE(PASSED);
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
	enum arguments_test_err_case test_error = NB_ERROR_CASE;
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_generate_key_args args = { 0 };
	struct smw_generate_key_args *smw_gen_args = NULL;
	struct key_identifier_node *key_node;
	json_object *key_id_obj = NULL;
	json_object *size_obj = NULL;
	json_object *test_err_obj = NULL;

	if (!params || !key_identifiers || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* 'security_size' is a mandatory parameter */
	if (!json_object_object_get_ex(params, SEC_SIZE_OBJ, &size_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "security_size");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* 'key_id' is a mandatory parameter */
	if (!json_object_object_get_ex(params, KEY_ID_OBJ, &key_id_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	args.version = common_params->version;

	if (!strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	key_descriptor.type_name = key_type;
	key_descriptor.security_size = json_object_get_int(size_obj);

	/* Specific test cases */
	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &test_err_obj)) {
		res = get_test_err_status(&test_error,
					  json_object_get_string(test_err_obj));
		if (res != ERR_CODE(PASSED))
			return res;

		/*
		 * If test error is ARGS_NULL nothing has to be done. This
		 * case call smw_generate_key with NULL argument.
		 */
		if (test_error != ARGS_NULL) {
			res = set_gen_bad_args(test_error, &smw_gen_args, &args,
					       &key_descriptor, &key_buffer);

			if (res != ERR_CODE(PASSED))
				return res;
		}
	} else {
		args.key_descriptor = &key_descriptor;
		key_descriptor.buffer = &key_buffer;

		/* Set optional parameters */
		res = set_gen_opt_params(params, &args);
		if (res != ERR_CODE(PASSED))
			return res;

		smw_gen_args = &args;
	}

	/* Call generate key function and compare result with expected one */
	*ret_status = smw_generate_key(smw_gen_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK) {
		/* Save key identifier if a key is generated */
		key_node = malloc(sizeof(struct key_identifier_node));
		if (!key_node) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		key_node->id = json_object_get_int(key_id_obj);
		key_node->key_identifier = args.key_descriptor->id;
		key_node->next = NULL;

		res = key_identifier_add_list(key_identifiers, key_node);
		if (res != ERR_CODE(PASSED))
			free(key_node);
	}

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
	enum arguments_test_err_case test_error = NB_ERROR_CASE;
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_delete_key_args args = { 0 };
	struct smw_delete_key_args *smw_del_args = NULL;
	json_object *key_id_obj = NULL;
	json_object *test_err_obj = NULL;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* 'key_id' is a mandatory parameter */
	if (!json_object_object_get_ex(params, KEY_ID_OBJ, &key_id_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	args.version = common_params->version;

	/* Specific test cases */
	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &test_err_obj)) {
		res = get_test_err_status(&test_error,
					  json_object_get_string(test_err_obj));
		if (res != ERR_CODE(PASSED))
			return res;

		/*
		 * If test error is ARGS_NULL nothing has to be done. This
		 * case call smw_delete_key with NULL argument.
		 */
		if (test_error != ARGS_NULL) {
			res = set_del_bad_args(test_error, &smw_del_args, &args,
					       &key_descriptor);

			if (res != ERR_CODE(PASSED))
				return res;
		}
	} else {
		/* Fill delete key args */
		args.key_descriptor = &key_descriptor;
		key_descriptor.id =
			find_key_identifier(key_identifiers,
					    json_object_get_int(key_id_obj));
		smw_del_args = &args;
	}

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
	enum arguments_test_err_case test_error = NB_ERROR_CASE;
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_import_key_args args = { 0 };
	struct smw_import_key_args *smw_import_args = NULL;
	struct key_identifier_node *key_node;
	json_object *key_id_obj = NULL;
	json_object *size_obj = NULL;
	json_object *test_err_obj = NULL;

	if (!params || !common_params || !key_identifiers || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* 'security_size' is a mandatory parameter */
	if (!json_object_object_get_ex(params, SEC_SIZE_OBJ, &size_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "security_size");
		return ERR_CODE(MISSING_PARAMS);
	}

	/* 'key_id' is a mandatory parameter */
	if (!json_object_object_get_ex(params, KEY_ID_OBJ, &key_id_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	args.version = common_params->version;

	if (!strcmp(common_params->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = common_params->subsystem;

	key_descriptor.type_name = key_type;
	key_descriptor.security_size = json_object_get_int(size_obj);

	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &test_err_obj)) {
		/* Specific test cases parameters */
		res = get_test_err_status(&test_error,
					  json_object_get_string(test_err_obj));
		if (res != ERR_CODE(PASSED))
			return res;

		/*
		 * If test error is ARGS_NULL nothing has to be done. This
		 * case call smw_import_key with NULL argument.
		 */
		if (test_error != ARGS_NULL) {
			res = set_import_bad_args(test_error, &smw_import_args,
						  &args, &key_descriptor,
						  &key_buffer);

			if (res != ERR_CODE(PASSED))
				return res;
		}
	} else {
		args.key_descriptor = &key_descriptor;
		key_descriptor.buffer = &key_buffer;

		/* Set optional parameters */
		res = set_import_opt_params(params, &args);
		if (res != ERR_CODE(PASSED))
			return res;

		smw_import_args = &args;
	}

	/* Call import key function and compare result with expected one */
	*ret_status = smw_import_key(smw_import_args);

	if (CHECK_RESULT(*ret_status, common_params->expected_res)) {
		res = ERR_CODE(BAD_RESULT);
		goto exit;
	}

	if (*ret_status == SMW_STATUS_OK) {
		/* Save key identifier if a key is imported */
		key_node = malloc(sizeof(struct key_identifier_node));
		if (!key_node) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		key_node->id = json_object_get_int(key_id_obj);
		key_node->key_identifier = args.key_descriptor->id;
		key_node->next = NULL;

		res = key_identifier_add_list(key_identifiers, key_node);
		if (res != ERR_CODE(PASSED))
			free(key_node);
	}

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
	enum arguments_test_err_case test_error = NB_ERROR_CASE;
	struct smw_export_key_args args = { 0 };
	struct smw_export_key_args *smw_export_args = &args;
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_keypair_buffer exp_key_buffer = { 0 };

	json_object *key_id_obj = NULL;
	json_object *test_err_obj = NULL;

	if (!params || !common_params || !ret_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* 'key_id' is a mandatory parameter */
	if (!json_object_object_get_ex(params, KEY_ID_OBJ, &key_id_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "key_id");
		return ERR_CODE(MISSING_PARAMS);
	}

	args.version = common_params->version;
	args.key_descriptor = &key_descriptor;
	key_descriptor.buffer = &key_buffer;

	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &test_err_obj)) {
		/* Specific test cases parameters */
		res = get_test_err_status(&test_error,
					  json_object_get_string(test_err_obj));
		if (res != ERR_CODE(PASSED))
			return res;

		res = set_export_bad_args(test_error, &smw_export_args);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else {
		key_descriptor.id =
			find_key_identifier(key_identifiers,
					    json_object_get_int(key_id_obj));

		status = smw_get_security_size(&key_descriptor);
		if (status != SMW_STATUS_OK)
			return ERR_CODE(BAD_RESULT);

		status = smw_get_key_type_name(&key_descriptor);
		if (status != SMW_STATUS_OK)
			return ERR_CODE(BAD_RESULT);

		res = set_export_opt_params(params, &args, &exp_key_buffer,
					    export_type);
		if (res != ERR_CODE(PASSED))
			goto exit;
	}

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
		free(exp_key_buffer.private_data);

	if (args.key_attributes_list)
		free((void *)args.key_attributes_list);

	return res;
}
