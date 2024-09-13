// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <smw/names.h>
#include <smw/object.h>

#include "types.h"
#include "util.h"
#include "util_attr.h"
#include "data.h"
#include "key.h"

bool is_data_object(const char *object_name)
{
	static const char data_name[] = "data";

	if (memcmp(object_name, data_name, sizeof(data_name) - 1) == 0)
		return true;

	return false;
}

bool is_key_object(const char *object_name)
{
	static const char key_name[] = "key";

	if (memcmp(object_name, key_name, sizeof(key_name) - 1) == 0)
		return true;

	return false;
}

int key_type_to_object_type(smw_key_type_t key_type_name,
			    smw_object_type_t *obj_type_name)
{
	switch (key_type_name) {
	case SMW_KEY_TYPE_NAME_SECP_R1:
	case SMW_KEY_TYPE_NAME_BRAINPOOL_R1:
	case SMW_KEY_TYPE_NAME_BRAINPOOL_T1:
	case SMW_KEY_TYPE_NAME_ED25519:
	case SMW_KEY_TYPE_NAME_DSA_SM2_FP:
	case SMW_KEY_TYPE_NAME_RSA:
	case SMW_KEY_TYPE_NAME_RAW:
		*obj_type_name = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		break;

	case SMW_KEY_TYPE_NAME_AES:
	case SMW_KEY_TYPE_NAME_DES:
	case SMW_KEY_TYPE_NAME_DES3:
	case SMW_KEY_TYPE_NAME_SM4:
	case SMW_KEY_TYPE_NAME_HMAC:
	case SMW_KEY_TYPE_NAME_TLS_MASTER:
	case SMW_KEY_TYPE_NAME_DERIVE:
		*obj_type_name = SMW_OBJECT_TYPE_NAME_SECRET_KEY;
		break;

	default:
		*obj_type_name = SMW_OBJECT_TYPE_NAME_NONE;
		break;
	}

	return ERR_CODE(PASSED);
}

int object_read_attributes(struct json_object *params,
			   smw_attr_attributes_t *attributes)
{
	if (!params || !attributes) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	*attributes = 0;

	return util_attr_read_attributes(params, ATTR_LIST_OBJ,
					 &attributes_callback, attributes);
}

int object_read_descriptor(struct subtest_data *subtest,
			   struct smw_object_descriptor *object_descriptor,
			   const char *object_name)
{
	int res = ERR_CODE(BAD_ARGS);
	struct smw_data_attributes data_attributes = { 0 };
	struct keypair_ops key = { 0 };
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_key_attributes *key_attributes_ptr = NULL;
	struct json_object *okey_params = NULL;

	struct smw_data_descriptor *data_descriptor_ptr =
		&object_descriptor->data;
	struct smw_key_descriptor *key_descriptor_ptr = &object_descriptor->key;

	if (is_data_object(object_name)) {
		data_descriptor_ptr->data_attributes = &data_attributes;

		res = data_read_descriptor(list_data(subtest),
					   data_descriptor_ptr, object_name);

		if (res == ERR_CODE(PASSED)) {
			object_descriptor->id = data_descriptor_ptr->identifier;
			object_descriptor->type = SMW_OBJECT_TYPE_NAME_DATA;
			object_descriptor->attributes =
				data_descriptor_ptr->data_attributes->attributes;
		}

	} else if (is_key_object(object_name)) {
		res = key_read_descriptor(list_keys(subtest), &key,
					  object_name);

		if (res == ERR_CODE(PASSED)) {
			object_descriptor->key = key.desc;
			object_descriptor->id = key_descriptor_ptr->id;

			res = key_type_to_object_type(key.desc.type_name,
						      &object_descriptor->type);
			if (res != ERR_CODE(PASSED))
				return res;

			res = util_key_get_key_params(subtest, OBJECT_NAME,
						      &okey_params);
			if (res != ERR_CODE(PASSED))
				return res;

			key_attributes_ptr = &key_attributes;
			res = key_read_attributes(okey_params,
						  &key_attributes_ptr);
			if (res != ERR_CODE(PASSED))
				return res;

			if (key_attributes_ptr) {
				object_descriptor->attributes =
					key_attributes_ptr->attributes;
			}
		}
	}

	return res;
}

int object_find_test_args_null(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	const char *object_name = NULL;
	smw_attr_attributes_t object_attributes = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&object_name, OBJECT_NAME, t_string,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND)) {
		res = object_read_attributes(subtest->params,
					     &object_attributes);
	}

	if (res != ERR_CODE(PASSED))
		goto exit;

	if (object_name)
		subtest->smw_status = smw_find_object_db(NULL);
	else if (object_attributes)
		subtest->smw_status = smw_find_object_db_init(NULL, 0, NULL);
	else
		subtest->smw_status = SMW_STATUS_UNKNOWN_ID;

	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	return res;
}

int object_find_no_test_error(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_object_descriptor object_descriptor = { 0 };
	const char *object_name = NULL;
	uint32_t found = 0;
	uint32_t object_found = 0;
	smw_attr_attributes_t object_attributes = 0;
	void *ctx = NULL;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&object_name, OBJECT_NAME, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		res = object_read_descriptor(subtest, &object_descriptor,
					     object_name);
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		res = object_read_attributes(subtest->params,
					     &object_attributes);
	}

	if (res != ERR_CODE(PASSED))
		goto exit;

	if (object_name) {
		subtest->smw_status = smw_find_object_db(&object_descriptor);
		if (subtest->smw_status == SMW_STATUS_OK)
			found++;
	} else if (object_attributes) {
		subtest->smw_status =
			smw_find_object_db_init(&ctx, object_attributes,
						&object_descriptor);
		if (subtest->smw_status == SMW_STATUS_OK) {
			while (smw_find_object_db_next(ctx,
						       &object_descriptor) ==
			       SMW_STATUS_OK) {
				found++;
			}

			subtest->smw_status = smw_find_object_db_final(ctx);
		}
	} else {
		subtest->smw_status = SMW_STATUS_UNKNOWN_ID;
	}

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_read_json_type(&object_found, OBJECT_FOUND, t_uint,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		if (found != object_found)
			res = ERR_CODE(FAILED);
		else
			DBG_PRINT("Found %l objects", found);
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		if (found == 1) {
			DBG_PRINT("Found one object");
			res = ERR_CODE(PASSED);
		} else {
			res = ERR_CODE(FAILED);
		}
	}

exit:
	return res;
}

int object_find(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_test_error(&error, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	switch (error) {
	case NOT_DEFINED:
		res = object_find_no_test_error(subtest);
		break;

	case ARGS_NULL:
		res = object_find_test_args_null(subtest);
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		res = ERR_CODE(BAD_PARAM_TYPE);
	}

	return res;
}
