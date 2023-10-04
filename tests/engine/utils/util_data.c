// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <json.h>

#include "util.h"
#include "util_data.h"
#include "util_list.h"

static void data_free_data(void *data)
{
	if (data)
		free(data);
}

static int data_add_node(struct llist *data_list, const char *data_name,
			 void *odata_params)
{
	int res = ERR_CODE(BAD_ARGS);

	struct data_info *info = NULL;

	if (!data_list || !data_name)
		return res;

	info = calloc(1, sizeof(*info));
	if (!info) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	info->odata_params = odata_params;

	res = util_list_add_node(data_list, (uintptr_t)data_name, info);

	if (res != ERR_CODE(PASSED) && info)
		free(info);

	return res;
}

static int register_data(struct json_object *odata, struct llist *data_list)
{
	int res = ERR_CODE(PASSED);
	struct json_object_iter odata_params = { 0 };
	void *data = NULL;

	if (!json_object_get_object(odata))
		return ERR_CODE(BAD_ARGS);

	json_object_object_foreachC(odata, odata_params)
	{
		if (!json_object_get_object(odata_params.val)) {
			DBG_PRINT("Ignore %s", odata_params.key);
			continue;
		}

		res = util_list_find_node(data_list,
					  (uintptr_t)odata_params.key, &data);
		if (res != ERR_CODE(PASSED))
			return res;

		if (data) {
			DBG_PRINT("Data already registered: %s",
				  odata_params.key);
			return ERR_CODE(BAD_ARGS);
		}

		res = data_add_node(data_list, odata_params.key,
				    odata_params.val);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	return res;
}

static int build_data_list(char *dir_def_file, struct json_object *definition,
			   struct llist *data_list, struct llist *files)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *odata_list = NULL;
	struct json_object *odef = NULL;
	struct json_object_iter obj = { 0 };
	char *def_file = NULL;
	void *dummy = NULL;

	if (!definition || !data_list)
		return res;

	res = util_read_json_type(&odata_list, DATA_LIST_OBJ, t_object,
				  definition);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		return res;

	if (res == ERR_CODE(PASSED)) {
		res = register_data(odata_list, data_list);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	res = util_read_json_type(&def_file, FILEPATH_OBJ, t_string,
				  definition);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		return res;

	if (res == ERR_CODE(PASSED) &&
	    check_file_extension(def_file, DEFINITION_FILE_EXTENSION) ==
		    ERR_CODE(PASSED)) {
		res = util_read_json_file(dir_def_file, def_file, &odef);

		if (res == ERR_CODE(PASSED)) {
			res = util_list_find_node(files, (uintptr_t)def_file,
						  &dummy);
			if (res != ERR_CODE(PASSED))
				return res;

			if (dummy) {
				DBG_PRINT("Error: nested file inclusion (%s)",
					  def_file);
				return ERR_CODE(BAD_ARGS);
			}

			/*
			 * Add a node in list files with id set to def_file.
			 * No data is stored by the node. But data pointer must be different to NULL
			 * in order to detect later if the node is found in the list.
			 * Data pointer is not freed when the list is cleared
			 * because the method to free the data is set to NULL
			 * when list is initialized.
			 */
			res = util_list_add_node(files, (uintptr_t)def_file,
						 (void *)1);
			if (res != ERR_CODE(PASSED))
				return res;

			res = build_data_list(dir_def_file, odef, data_list,
					      files);
			if (res != ERR_CODE(PASSED))
				return res;
		} else {
			DBG_PRINT("Ignore file: %s", def_file);
			res = ERR_CODE(PASSED);
		}
	}

	if (!json_object_get_object(definition))
		return ERR_CODE(PASSED);

	json_object_object_foreachC(definition, obj)
	{
		if (!strcmp(obj.key, DATA_LIST_OBJ))
			continue;

		if (json_object_get_type(obj.val) == json_type_object) {
			res = build_data_list(dir_def_file, obj.val, data_list,
					      files);
			if (res != ERR_CODE(PASSED))
				return res;
		}
	}

	return ERR_CODE(PASSED);
}

int util_data_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, data_free_data, LIST_ID_TYPE_STRING);
}

int util_data_build_data_list(char *dir_def_file,
			      struct json_object *definition,
			      struct llist *data_list)
{
	int res = ERR_CODE(PASSED);
	int err = ERR_CODE(PASSED);

	struct llist *files = NULL;

	res = util_list_init(&files, NULL, LIST_ID_TYPE_STRING);

	if (res == ERR_CODE(PASSED))
		res = build_data_list(dir_def_file, definition, data_list,
				      files);

	err = util_list_clear(files);
	if (res == ERR_CODE(PASSED))
		res = err;

	return res;
}
