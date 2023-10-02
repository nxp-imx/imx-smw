// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <psa/internal_trusted_storage.h>

#include "types.h"
#include "util.h"
#include "data.h"

static void free_data(struct data_descriptor *data_descriptor)
{
	if (data_descriptor->data)
		free(data_descriptor->data);
}

int storage_store_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct data_descriptor data_descriptor = { 0 };
	const char *data_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&data_name, DATA_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		res = data_read_descriptor_psa(list_data(subtest),
					       &data_descriptor, data_name);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	subtest->psa_status =
		psa_its_set(data_descriptor.uid, data_descriptor.length,
			    data_descriptor.data, data_descriptor.create_flags);

	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	free_data(&data_descriptor);

	return res;
}

int storage_retrieve_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct data_descriptor data_descriptor = { 0 };
	const char *data_name = NULL;
	unsigned int offset = 0;
	unsigned char *expected_data = NULL;
	unsigned int expected_data_length = 0;
	bool no_output = false;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&data_name, DATA_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		res = data_read_descriptor_psa(list_data(subtest),
					       &data_descriptor, data_name);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	res = util_read_json_type(&offset, OFFSET_OBJ, t_int, subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = util_read_hex_buffer(&expected_data, &expected_data_length,
				   subtest->params, OUTPUT_OBJ);
	if (res == ERR_CODE(MISSING_PARAMS)) {
		no_output = true;
		res = ERR_CODE(PASSED);
	} else if (res != ERR_CODE(PASSED)) {
		goto exit;
	}

	subtest->psa_status =
		psa_its_get(data_descriptor.uid, offset, data_descriptor.length,
			    data_descriptor.data, &data_descriptor.length);
	if (subtest->psa_status == PSA_ERROR_BUFFER_TOO_SMALL &&
	    data_descriptor.length) {
		if (data_descriptor.data)
			free(data_descriptor.data);

		data_descriptor.data = calloc(1, data_descriptor.length);
		if (!data_descriptor.data) {
			DBG_PRINT_ALLOC_FAILURE();
			res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
			goto exit;
		}

		subtest->psa_status = psa_its_get(data_descriptor.uid, offset,
						  data_descriptor.length,
						  data_descriptor.data,
						  &data_descriptor.length);
	}

	if (subtest->psa_status != PSA_SUCCESS) {
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

int storage_delete_psa(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct data_descriptor data_descriptor = { 0 };
	const char *data_name = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&data_name, DATA_NAME_OBJ, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		res = data_read_descriptor_psa(list_data(subtest),
					       &data_descriptor, data_name);
		if (res != ERR_CODE(PASSED))
			goto exit;
	} else if (res != ERR_CODE(VALUE_NOTFOUND)) {
		goto exit;
	}

	subtest->psa_status = psa_its_remove(data_descriptor.uid);
	if (subtest->psa_status != PSA_SUCCESS)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	free_data(&data_descriptor);

	return res;
}
