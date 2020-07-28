// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdio.h>

#include "json.h"
#include "util.h"
#include "types.h"
#include "smw_keymgr.h"
#include "smw_status.h"

int generate_key(json_object *args,
		 struct key_identifier_list **key_identifiers)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	int expected_result = SMW_STATUS_OPERATION_FAILURE;
	struct smw_key_identifier *key_identifier = NULL;
	struct smw_generate_key_args key_args = { 0 };
	struct key_identifier_data *data = NULL;
	json_object *version = NULL;
	json_object *subsystem = NULL;
	json_object *key_type = NULL;
	json_object *security_size = NULL;
	json_object *attributes = NULL;
	json_object *attributes_len = NULL;
	json_object *result = NULL;
	json_object *key_identifier_id = NULL;

	status = smw_alloc_key_identifier(&key_identifier);
	if (status) {
		printf("ERROR in %s. Key identifier allocation failed\n",
		       __func__);
		return 1;
	}

	/* Get all args objects */
	json_object_object_get_ex(args, VERSION_OBJ, &version);
	json_object_object_get_ex(args, SUBSYSTEM_OBJ, &subsystem);
	json_object_object_get_ex(args, KEY_TYPE_OBJ, &key_type);
	json_object_object_get_ex(args, SEC_SIZE_OBJ, &security_size);
	json_object_object_get_ex(args, ATTR_LIST_OBJ, &attributes);
	json_object_object_get_ex(args, ATTR_LIST_LEN_OBJ, &attributes_len);
	json_object_object_get_ex(args, RES_OBJ, &result);
	json_object_object_get_ex(args, KEY_ID_OBJ, &key_identifier_id);

	/* Fill generate key args */
	key_args.version = json_object_get_int(version);
	key_args.subsystem_name = json_object_get_string(subsystem);
	key_args.key_type_name = json_object_get_string(key_type);
	key_args.security_size = json_object_get_int(security_size);

	if (json_object_get_type(attributes) == json_type_null)
		key_args.key_attributes_list = NULL;
	else
		key_args.key_attributes_list =
			(unsigned char *)json_object_get_string(attributes);

	key_args.key_attributes_list_length =
		json_object_get_int(attributes_len);
	key_args.key_identifier = key_identifier;

	/* Call generate key function and compare result with expected one */
	status = smw_generate_key(&key_args);
	expected_result = json_object_get_int(result);

	if (status != expected_result) {
		printf("ERROR in %s. Result is %d and should be %d\n", __func__,
		       status, expected_result);
		return 1;
	}

	if (!status) {
		/* Save key identifier if a key is generated */
		data = malloc(sizeof(struct key_identifier_data));
		if (!data) {
			printf("ERROR in %s. Memory allocation failed\n",
			       __func__);
			return 1;
		}

		data->id = json_object_get_int(key_identifier_id);
		data->key_identifier = key_identifier;
		return key_identifier_add_list(key_identifiers, data);
	}

	return 0;
}

int delete_key(json_object *args, struct key_identifier_list *key_identifiers)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	int expected_result = SMW_STATUS_OPERATION_FAILURE;
	struct smw_delete_key_args key_args = { 0 };
	json_object *version = NULL;
	json_object *result = NULL;
	json_object *key_identifier_id = NULL;

	/* Get all args objects */
	json_object_object_get_ex(args, VERSION_OBJ, &version);
	json_object_object_get_ex(args, RES_OBJ, &result);
	json_object_object_get_ex(args, KEY_ID_OBJ, &key_identifier_id);

	/* Fill delete key args */
	key_args.version = json_object_get_int(version);
	key_args.key_identifier =
		find_key_identifier(key_identifiers,
				    json_object_get_int(key_identifier_id));

	/* Call delete key function and compare result with expected one */
	status = smw_delete_key(&key_args);
	expected_result = json_object_get_int(result);

	if (status != expected_result) {
		printf("ERROR in %s. Result is %d and should be %d\n", __func__,
		       status, expected_result);
		return 1;
	}

	/*
	 * Key identifier will be freed when the key identifiers linkes list
	 * will be cleared
	 */

	return 0;
}
