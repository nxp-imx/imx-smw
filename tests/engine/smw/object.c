// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
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

static void free_data(struct smw_data_descriptor *data_descriptor)
{
	if (data_descriptor->data) {
		free(data_descriptor->data);
		data_descriptor->data = NULL;
	}
}

static bool is_data_object(const char *object_name)
{
	static const char data_name[] = "data";

	if (memcmp(object_name, data_name, sizeof(data_name) - 1) == 0)
		return true;

	return false;
}

static bool is_key_object(const char *object_name)
{
	static const char key_name[] = "key";

	if (memcmp(object_name, key_name, sizeof(key_name) - 1) == 0)
		return true;

	return false;
}

static int key_type_to_object_type(smw_key_type_t key_type_name,
				   smw_object_type_t *obj_type_name)
{
	switch (key_type_name) {
	case SMW_KEY_TYPE_NAME_SECP_R1:
	case SMW_KEY_TYPE_NAME_BRAINPOOL_R1:
	case SMW_KEY_TYPE_NAME_BRAINPOOL_T1:
	case SMW_KEY_TYPE_NAME_ED25519:
	case SMW_KEY_TYPE_NAME_ED448:
	case SMW_KEY_TYPE_NAME_X25519:
	case SMW_KEY_TYPE_NAME_X448:
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

static int object_type_to_key_privacy(smw_object_type_t obj_type_name,
				      smw_key_privacy_t *key_privacy_name)
{
	switch (obj_type_name) {
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		*key_privacy_name = SMW_KEY_PRIVACY_NAME_PAIR;
		break;

	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
		*key_privacy_name = SMW_KEY_PRIVACY_NAME_PUBLIC;
		break;

	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
		*key_privacy_name = SMW_KEY_PRIVACY_NAME_SHARED_SECRET;
		break;

	default:
		return ERR_CODE(FAILED);
	}

	return ERR_CODE(PASSED);
}

static int object_check_privacy(struct smw_object_descriptor *object_descriptor,
				const char *privacy_string)
{
	int res = ERR_CODE(BAD_ARGS);
	smw_key_privacy_t key_privacy_name = SMW_KEY_PRIVACY_NAME_NONE;

	if (!object_descriptor)
		goto error;

	res = object_type_to_key_privacy(object_descriptor->type,
					 &key_privacy_name);
	if (res != ERR_CODE(PASSED))
		goto error;

	switch (key_privacy_name) {
	case SMW_KEY_PRIVACY_NAME_PAIR:
		if (strcmp(privacy_string, KEYPAIR_STR))
			goto error;

		break;

	case SMW_KEY_PRIVACY_NAME_PUBLIC:
		if (strcmp(privacy_string, PUBLIC_STR))
			goto error;

		break;

	case SMW_KEY_PRIVACY_NAME_SHARED_SECRET:
		if (strcmp(privacy_string, SECRET_STR))
			goto error;

		break;

	default:
		goto error;
	}

	return ERR_CODE(PASSED);

error:
	return ERR_CODE(FAILED);
}

static int
object_read_attributes(struct json_object *params,
		       struct smw_object_descriptor *object_descriptor)
{
	int res = ERR_CODE(PASSED);
	smw_attr_attributes_t obj_attr = 0;

	if (!params || !object_descriptor) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	res = util_attr_read_attributes(params, ATTR_LIST_OBJ,
					&attributes_callback, &obj_attr);
	if (res != ERR_CODE(VALUE_NOTFOUND) && res != ERR_CODE(PASSED))
		return res;

	object_descriptor->persistency =
		SMW_ATTR_SET_PERSISTENCE(0, SMW_ATTR_GET_PERSISTENCE(obj_attr));

	res = util_read_json_type(&object_descriptor->id, OBJECT_ID, t_uint,
				  params);
	if (res == ERR_CODE(VALUE_NOTFOUND))
		res = ERR_CODE(PASSED);

	return res;
}

static int
object_read_descriptor(struct subtest_data *subtest,
		       struct smw_object_descriptor *object_descriptor,
		       const char *object_name)
{
	int res = ERR_CODE(BAD_ARGS);
	struct keypair_ops key = { 0 };
	struct smw_key_attributes *key_attributes = NULL;
	struct json_object *okey_params = NULL;
	struct smw_data_descriptor *data_descriptor = &object_descriptor->data;

	if (is_data_object(object_name)) {
		res = data_read_descriptor(list_data(subtest), data_descriptor,
					   object_name);

		if (res == ERR_CODE(PASSED)) {
			object_descriptor->id = data_descriptor->identifier;
			object_descriptor->type = SMW_OBJECT_TYPE_NAME_DATA;
			object_descriptor->data.attributes.attributes =
				data_descriptor->attributes.attributes;
		}

	} else if (is_key_object(object_name)) {
		res = key_read_descriptor(list_keys(subtest), &key,
					  object_name);

		if (res == ERR_CODE(PASSED)) {
			object_descriptor->key = key.desc;
			object_descriptor->id = key.desc.id;

			res = key_type_to_object_type(key.desc.type_name,
						      &object_descriptor->type);
			if (res != ERR_CODE(PASSED))
				return res;

			res = util_key_get_key_params(subtest, OBJECT_NAME,
						      &okey_params);
			if (res != ERR_CODE(PASSED))
				return res;

			key_attributes = &object_descriptor->key.attributes;
			res = key_read_attributes(okey_params, key_attributes);
			if (res != ERR_CODE(PASSED))
				return res;
		}
	}

	return res;
}

static int object_find_test_args_null(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	const char *object_name = NULL;
	struct smw_object_descriptor object_descriptor = { 0 };

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_read_json_type(&object_name, OBJECT_NAME, t_string,
				  subtest->params);
	if (res == ERR_CODE(VALUE_NOTFOUND)) {
		res = object_read_attributes(subtest->params,
					     &object_descriptor);
	}

	if (res != ERR_CODE(PASSED))
		goto exit;

	if (object_descriptor.id)
		subtest->smw_status = smw_find_object_db(NULL);
	else
		subtest->smw_status = smw_find_object_db_init(NULL);

	if (subtest->smw_status != SMW_STATUS_OK)
		res = ERR_CODE(API_STATUS_NOK);

exit:
	return res;
}

static int object_find_no_test_error(struct subtest_data *subtest)
{
	int res = ERR_CODE(BAD_ARGS);

	struct smw_find_object_db_args args = { 0 };
	struct smw_object_descriptor object_descriptor = { 0 };
	const char *object_name = NULL;
	const char *privacy_string = NULL;
	uint32_t found = 0;
	uint32_t object_found = 0;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	args.version = subtest->version;

	res = util_read_json_type(&object_name, OBJECT_NAME, t_string,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		res = object_read_descriptor(subtest, &object_descriptor,
					     object_name);
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		res = object_read_attributes(subtest->params,
					     &object_descriptor);
	}

	if (res != ERR_CODE(PASSED))
		goto exit;

	args.object_descriptor = &object_descriptor;

	if (object_descriptor.id) {
		subtest->smw_status = smw_find_object_db(&args);
		if (subtest->smw_status == SMW_STATUS_OK)
			found++;

		if (object_descriptor.label)
			free(object_descriptor.label);

		if (object_descriptor.user_id)
			free(object_descriptor.user_id);

		if (object_descriptor.type == SMW_OBJECT_TYPE_NAME_DATA)
			free_data(&object_descriptor.data);
	} else {
		subtest->smw_status = smw_find_object_db_init(&args);
		if (subtest->smw_status == SMW_STATUS_OK) {
			while (smw_find_object_db_next(&args) ==
			       SMW_STATUS_OK) {
				found++;
				if (object_descriptor.label) {
					free(object_descriptor.label);
					object_descriptor.label = NULL;
				}

				if (object_descriptor.user_id) {
					free(object_descriptor.user_id);
					object_descriptor.user_id = NULL;
				}

				if (object_descriptor.type ==
				    SMW_OBJECT_TYPE_NAME_DATA) {
					free_data(&object_descriptor.data);
					memset(&object_descriptor.data, 0,
					       sizeof(struct smw_data_descriptor));
				} else {
					memset(&object_descriptor.key, 0,
					       sizeof(struct smw_key_descriptor));
				}
			}

			subtest->smw_status = smw_find_object_db_final(&args);
		}
	}

	if (subtest->smw_status != SMW_STATUS_OK) {
		res = ERR_CODE(API_STATUS_NOK);
		goto exit;
	}

	res = util_read_json_type(&object_found, OBJECT_FOUND, t_uint,
				  subtest->params);
	if (res == ERR_CODE(PASSED)) {
		if (found != object_found) {
			res = ERR_CODE(FAILED);
			goto exit;
		} else {
			DBG_PRINT("Found %l objects", found);
		}
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		if (found == 1) {
			DBG_PRINT("Found one object");
			res = ERR_CODE(PASSED);
		} else {
			res = ERR_CODE(FAILED);
			goto exit;
		}
	}

	if (found == 1) {
		res = util_read_json_type(&privacy_string, PRIVACY_OBJ,
					  t_string, subtest->params);
		if (res == ERR_CODE(PASSED))
			res = object_check_privacy(&object_descriptor,
						   privacy_string);
		else if (res == ERR_CODE(VALUE_NOTFOUND))
			res = ERR_CODE(PASSED);
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
