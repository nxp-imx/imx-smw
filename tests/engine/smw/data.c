// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "types.h"
#include "util.h"
#include "util_data.h"
#include "util_attr.h"

#include "data.h"

static const struct util_attr_info attributes_info[] = {
	ATTR_LIFECYCLE(CURRENT),     ATTR_LIFECYCLE(OPEN),
	ATTR_LIFECYCLE(CLOSED),	     ATTR_LIFECYCLE(CLOSED_LOCKED),
	ATTR_RW_FLAGS(READ_ONCE),    ATTR_RW_FLAGS(READ_ONLY),
	ATTR_PERSISTENCE(TRANSIENT), ATTR_PERSISTENCE(PERSISTENT),
	ATTR_PERSISTENCE(PERMANENT), { .name = NULL }
};

static void attributes_callback(void *user_data, const char *attributes[],
				size_t n_attributes)
{
	smw_attr_attributes_t *rw_flags = user_data;
	size_t i = 0;

	for (; i < n_attributes; i++)
		*rw_flags |=
			ATTR_ARRAY_FIND_MATCH(attributes_info, attributes[i])
				.smw_attributes;

	DBG_PRINT("SMW RW flags: %08x", *rw_flags);
}

static int read_data_attributes(struct json_object *params,
				struct smw_data_attributes **data_attributes)
{
	int ret = ERR_CODE(PASSED);
	int found = 0;

	if (!params || !data_attributes || !*data_attributes) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_attr_read_attributes(params, ATTR_LIST_OBJ,
					&attributes_callback,
					&((*data_attributes)->attributes));
	if (ret == ERR_CODE(PASSED))
		found++;
	else if (ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_attr_read_attributes(params, LIFECYCLE_OBJ,
					&attributes_callback,
					&((*data_attributes)->attributes));
	if (ret == ERR_CODE(PASSED))
		found++;
	else if (ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (!found)
		*data_attributes = NULL;

	return ERR_CODE(PASSED);
}

static int read_descriptor(struct llist *data_list,
			   struct smw_data_descriptor *data_descriptor,
			   const char *data_name, struct llist *data_names)
{
	int ret = ERR_CODE(PASSED);
	struct data_info *info = NULL;
	const char *parent_data_name = NULL;
	void *dummy = NULL;

	if (!data_descriptor || !data_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_list_find_node(data_list, (uintptr_t)data_name,
				  (void **)&info);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!info)
		return ERR_CODE(DATA_NOTFOUND);

	if (!info->odata_params)
		return ERR_CODE(PASSED);

	ret = util_read_json_type(&parent_data_name, DATA_NAME_OBJ, t_string,
				  info->odata_params);

	if (ret == ERR_CODE(PASSED) && parent_data_name) {
		ret = util_list_find_node(data_names,
					  (uintptr_t)parent_data_name, &dummy);
		if (ret != ERR_CODE(PASSED))
			return ret;

		if (dummy) {
			DBG_PRINT("Error: nested data definition (%s, %s)",
				  parent_data_name, data_name);
			return ERR_CODE(BAD_ARGS);
		}

		/*
		 * Add a node in list data_names with id set to parent_data_name.
		 * No data is stored by the node. But data pointer must be different to NULL
		 * in order to detect later if the node is found in the list.
		 * Data pointer is not freed when the list is cleared
		 * because the method to free the data is set to NULL
		 * when list is initialized.
		 */
		ret = util_list_add_node(data_names,
					 (uintptr_t)parent_data_name,
					 (void *)1);
		if (ret != ERR_CODE(PASSED))
			return ret;

		ret = read_descriptor(data_list, data_descriptor,
				      parent_data_name, data_names);
		if (ret != ERR_CODE(PASSED))
			return ret;
	} else if (ret != ERR_CODE(VALUE_NOTFOUND)) {
		return ret;
	}

	ret = util_read_json_type(&data_descriptor->identifier, ID_OBJ, t_uint,
				  info->odata_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_read_obj_value(&data_descriptor->data,
				  &data_descriptor->length, DATA_OBJ,
				  info->odata_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = read_data_attributes(info->odata_params,
				   &data_descriptor->data_attributes);
	if (ret != ERR_CODE(PASSED))
		return ret;

	return ERR_CODE(PASSED);
}

int data_read_descriptor(struct llist *data_list,
			 struct smw_data_descriptor *data_descriptor,
			 const char *data_name)
{
	int ret = ERR_CODE(PASSED);
	int err = ERR_CODE(PASSED);

	struct llist *data_names = NULL;

	ret = util_list_init(&data_names, NULL, LIST_ID_TYPE_STRING);

	if (ret == ERR_CODE(PASSED))
		ret = read_descriptor(data_list, data_descriptor, data_name,
				      data_names);

	err = util_list_clear(data_names);
	if (ret == ERR_CODE(PASSED))
		ret = err;

	return ret;
}
