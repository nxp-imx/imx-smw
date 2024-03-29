// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw_storage.h>

#include "types.h"
#include "util.h"
#include "data.h"
#include "key.h"

static void free_data(struct smw_data_descriptor *data_descriptor)
{
	if (data_descriptor->data)
		free(data_descriptor->data);

	if (data_descriptor->attributes_list)
		free(data_descriptor->attributes_list);
}

int storage_store(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_store_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct smw_data_descriptor *data_descriptor_ptr = NULL;
	struct smw_encryption_args encryption_args = { 0 };
	struct smw_sign_args sign_args = { 0 };
	struct smw_encryption_args *encryption_args_ptr = NULL;
	struct smw_sign_args *sign_args_ptr = NULL;
	struct keys encrypt_keys = { 0 };
	struct keypair_ops sign_key_test = { 0 };
	struct smw_keypair_buffer sign_key_buffer = { 0 };
	const char *data_name = NULL;
	const char *sign_key_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = util_read_json_type(&data_name, DATA_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		data_descriptor_ptr = &data_descriptor;

		res = data_read_descriptor(list_data(subtest), &data_descriptor,
					   data_name);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	res = util_read_hex_buffer(&encryption_args.iv,
				   &encryption_args.iv_length, subtest->params,
				   IV_OBJ);
	if (res == ERR_CODE(PASSED))
		encryption_args_ptr = &encryption_args;
	else if (res != ERR_CODE(MISSING_PARAMS))
		goto exit;

	res = key_read_descriptors(subtest, ENCRYPT_KEY_NAME_OBJ,
				   &encryption_args.nb_keys,
				   &encryption_args.keys_desc, &encrypt_keys);
	if (res == ERR_CODE(PASSED)) {
		encryption_args_ptr = &encryption_args;
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		encryption_args.nb_keys = 0;
		encryption_args.keys_desc = NULL;
		free_keys(&encrypt_keys);
	} else {
		goto exit;
	}

	res = util_read_json_type(&encryption_args.mode_name, MODE_OBJ,
				  t_string, subtest->params);
	if (res == ERR_CODE(PASSED))
		encryption_args_ptr = &encryption_args;
	else if (res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = util_read_json_type(&sign_key_name, SIGN_KEY_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		/* Initialize key descriptor */
		res = key_desc_init(&sign_key_test, &sign_key_buffer);
		if (res != ERR_CODE(PASSED))
			goto exit;

		/* Read the json-c key description */
		res = key_read_descriptor(list_keys(subtest), &sign_key_test,
					  sign_key_name);
		if (res != ERR_CODE(PASSED))
			goto exit;

		if (key_is_id_set(&sign_key_test))
			key_free_key(&sign_key_test);

		if (!key_is_id_set(&sign_key_test) &&
		    (!key_is_type_set(&sign_key_test) ||
		     !key_is_security_set(&sign_key_test) ||
		     !key_is_private_key_defined(&sign_key_test))) {
			DBG_PRINT_MISS_PARAM("Sign key description");
			res = ERR_CODE(MISSING_PARAMS);
			goto exit;
		}

		sign_args.key_descriptor = &sign_key_test.desc;
		sign_args_ptr = &sign_args;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	/* Get 'algo' optional parameter */
	res = util_read_json_type(&sign_args.algo_name, ALGO_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED))
		sign_args_ptr = &sign_args;
	else if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);
	else
		goto exit;

	args.data_descriptor = data_descriptor_ptr;
	args.encryption_args = encryption_args_ptr;
	args.sign_args = sign_args_ptr;

	subtest->smw_status = smw_store_data(&args);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	free_data(&data_descriptor);

	if (encryption_args.iv)
		free(encryption_args.iv);

	free_keys(&encrypt_keys);

	key_free_key(&sign_key_test);

	return res;
}

int storage_retrieve(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_retrieve_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct smw_data_descriptor *data_descriptor_ptr = NULL;
	const char *data_name = NULL;
	unsigned char *expected_data = NULL;
	unsigned int expected_data_length = 0;
	bool no_output = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = util_read_json_type(&data_name, DATA_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		data_descriptor_ptr = &data_descriptor;

		res = data_read_descriptor(list_data(subtest), &data_descriptor,
					   data_name);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	res = util_read_hex_buffer(&expected_data, &expected_data_length,
				   subtest->params, OUTPUT_OBJ);
	if (res == ERR_CODE(MISSING_PARAMS)) {
		no_output = true;
		res = ERR_CODE(PASSED);
	} else if (res != ERR_CODE(PASSED)) {
		goto exit;
	}

	args.data_descriptor = data_descriptor_ptr;

	subtest->smw_status = smw_retrieve_data(&args);
	if (subtest->smw_status == SMW_STATUS_OUTPUT_TOO_SHORT &&
	    data_descriptor.length) {
		if (data_descriptor.data)
			free(data_descriptor.data);

		data_descriptor.data = calloc(1, data_descriptor.length);
		if (!data_descriptor.data) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		subtest->smw_status = smw_retrieve_data(&args);
	}

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	if (!no_output) {
		res = util_compare_buffers(data_descriptor.data,
					   data_descriptor.length,
					   expected_data, expected_data_length);
	}

	DBG_DHEX("Retrieved data", data_descriptor.data,
		 data_descriptor.length);

exit:
	free_data(&data_descriptor);

	if (expected_data)
		free(expected_data);

	return res;
}

int storage_delete(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_delete_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	struct smw_data_descriptor *data_descriptor_ptr = NULL;
	const char *data_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	if (!strcmp(subtest->subsystem, "DEFAULT"))
		args.subsystem_name = NULL;
	else
		args.subsystem_name = subtest->subsystem;

	res = util_read_json_type(&data_name, DATA_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		data_descriptor_ptr = &data_descriptor;

		res = data_read_descriptor(list_data(subtest), &data_descriptor,
					   data_name);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	args.data_descriptor = data_descriptor_ptr;

	subtest->smw_status = smw_delete_data(&args);
	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	free_data(&data_descriptor);

	return res;
}
