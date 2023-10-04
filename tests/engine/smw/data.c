// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "types.h"
#include "util.h"
#include "util_data.h"
#include "util_tlv.h"

#include "data.h"

static int read_descriptor(struct llist *data_list,
			   struct smw_data_descriptor *data_descriptor,
			   const char *data_name, struct llist *data_names)
{
	int ret = ERR_CODE(PASSED);
	struct data_info *info = NULL;
	unsigned char *attrs = NULL;
	unsigned int attrs_len = 0;
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

	ret = util_read_json_type(&data_descriptor->identifier, ID_OBJ, t_int,
				  info->odata_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_read_hex_buffer(&data_descriptor->data,
				   &data_descriptor->length, info->odata_params,
				   DATA_OBJ);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(MISSING_PARAMS))
		return ret;

	ret = util_tlv_read_attrs(&attrs, &attrs_len, info->odata_params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (attrs && attrs_len) {
		if (data_descriptor->attributes_list)
			free(data_descriptor->attributes_list);

		data_descriptor->attributes_list = attrs;
		data_descriptor->attributes_list_length = attrs_len;
	}

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
