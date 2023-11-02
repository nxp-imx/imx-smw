// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <json.h>

#include "util.h"
#include "util_file.h"
#include "util_key.h"
#include "util_list.h"

static void key_free_data(void *data)
{
	struct key_data *key_data = data;

	if (key_data) {
		if (key_data->pub_key.data)
			free(key_data->pub_key.data);

		free(data);
	}
}

static int register_keys(struct json_object *okeys, struct llist *keys)
{
	int res = ERR_CODE(PASSED);
	struct json_object_iter okey_params = { 0 };
	void *data = NULL;

	if (!json_object_get_object(okeys))
		return ERR_CODE(BAD_ARGS);

	json_object_object_foreachC(okeys, okey_params)
	{
		if (!json_object_get_object(okey_params.val)) {
			DBG_PRINT("Ignore %s", okey_params.key);
			continue;
		}

		res = util_list_find_node(keys, (uintptr_t)okey_params.key,
					  &data);
		if (res != ERR_CODE(PASSED))
			return res;

		if (data) {
			DBG_PRINT("Key already registered: %s",
				  okey_params.key);
			return ERR_CODE(BAD_ARGS);
		}

		res = util_key_add_node(keys, okey_params.key, okey_params.val);
		if (res != ERR_CODE(PASSED))
			return res;
	}

	return res;
}

static int build_keys_list(char *dir_def_file, struct json_object *definition,
			   struct llist *keys, struct llist *files)
{
	int res = ERR_CODE(BAD_ARGS);
	struct json_object *okeys = NULL;
	struct json_object *odef = NULL;
	struct json_object_iter obj = { 0 };
	char *def_file = NULL;
	void *dummy = NULL;

	if (!definition || !keys)
		return res;

	res = util_read_json_type(&okeys, KEYS_OBJ, t_object, definition);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		return res;

	if (res == ERR_CODE(PASSED)) {
		res = register_keys(okeys, keys);
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

			res = build_keys_list(dir_def_file, odef, keys, files);
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
		if (!strcmp(obj.key, KEYS_OBJ) ||
		    !strncmp(obj.key, SUBTEST_OBJ, SUBTEST_OBJ_LEN))
			continue;

		if (json_object_get_type(obj.val) == json_type_object) {
			res = build_keys_list(dir_def_file, obj.val, keys,
					      files);
			if (res != ERR_CODE(PASSED))
				return res;
		}
	}

	return ERR_CODE(PASSED);
}

static int save_keys_to_json_file(struct llist *key_list, char *filepath)
{
	int res = ERR_CODE(BAD_ARGS);
	void *node = NULL;
	uintptr_t key_name = 0;
	struct key_data *data = NULL;
	struct json_object *global_obj = NULL;
	struct json_object *keys_obj = NULL;
	struct json_object *key_obj = NULL;
	struct json_object *key_identifier_obj = NULL;
	FILE *json_file = NULL;
	int nb_char = 0;

	if (!key_list || !filepath) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = check_file_extension(filepath, DEFINITION_FILE_EXTENSION);
	if (res != ERR_CODE(PASSED))
		return res;

	json_file = fopen(filepath, "w");
	if (!json_file) {
		DBG_PRINT("fopen %s failure %s", filepath, util_get_strerr());
		return ERR_CODE(INTERNAL);
	}

	global_obj = json_object_new_object();
	if (!global_obj) {
		DBG_PRINT("Can't create a new json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	keys_obj = json_object_new_object();
	if (!keys_obj) {
		DBG_PRINT("Can't create a new json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	if (json_object_object_add(global_obj, KEYS_OBJ, keys_obj)) {
		DBG_PRINT("Can't add a json object");
		res = ERR_CODE(INTERNAL);
		goto exit;
	}

	node = util_list_next(key_list, node, &key_name);

	while (node) {
		data = util_list_data(node);
		if (!data) {
			DBG_PRINT("Can't get the key data");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		key_obj = json_object_new_object();
		if (!key_obj) {
			DBG_PRINT("Can't create a new json object");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		key_identifier_obj = json_object_new_int64(0);
		if (!key_identifier_obj) {
			DBG_PRINT("Can't create a new json object");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		if (!json_object_set_int64(key_identifier_obj,
					   data->identifier)) {
			DBG_PRINT("json_object_set_int64() failed");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		if (json_object_object_add(key_obj, ID_OBJ,
					   key_identifier_obj)) {
			DBG_PRINT("Can't add a json object");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		key_identifier_obj = NULL;

		if (json_object_object_add(keys_obj, (const char *)key_name,
					   key_obj)) {
			DBG_PRINT("Can't add a json object");
			res = ERR_CODE(INTERNAL);
			goto exit;
		}

		key_obj = NULL;

		node = util_list_next(key_list, node, &key_name);
	}

	nb_char = fprintf(json_file, "%s\n",
			  json_object_to_json_string(global_obj));
	if (nb_char < 0) {
		DBG_PRINT("error %s", util_get_strerr());
		res = ERR_CODE(INTERNAL);
	}

exit:

	if (fflush(json_file)) {
		DBG_PRINT("fflush %s failure %s", filepath, util_get_strerr());

		if (res == ERR_CODE(PASSED))
			res = ERR_CODE(INTERNAL);
	}

	if (fclose(json_file)) {
		DBG_PRINT("fclose %s failure %s", filepath, util_get_strerr());

		if (res == ERR_CODE(PASSED))
			res = ERR_CODE(INTERNAL);
	}

	/* Free json objects */
	if (global_obj)
		json_object_put(global_obj);

	if (key_obj)
		json_object_put(key_obj);

	if (key_identifier_obj)
		json_object_put(key_identifier_obj);

	return res;
}

static int restore_keys_from_json_file(struct subtest_data *subtest,
				       char *filepath)
{
	int res = ERR_CODE(FAILED);
	struct json_object *restore_obj = NULL;
	struct json_object *okeys = NULL;
	struct json_object_iter okey_params = { 0 };
	struct key_data key_data = { 0 };
	int64_t key_id = 0;

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

	res = util_read_json_type(&okeys, KEYS_OBJ, t_object, restore_obj);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!json_object_get_object(okeys))
		return ERR_CODE(BAD_ARGS);

	json_object_object_foreachC(okeys, okey_params)
	{
		res = util_read_json_type(&key_id, ID_OBJ, t_int64,
					  okey_params.val);
		if (res != ERR_CODE(PASSED))
			return res;

		if (SET_OVERFLOW(key_id, key_data.identifier))
			return ERR_CODE(INTERNAL);

		/*
		 * Try to update the key in the list in case it's already
		 * present.
		 * Else create a new key in the list and add the information.
		 */
		res = util_key_update_node(list_keys(subtest), okey_params.key,
					   &key_data);
		if (res == ERR_CODE(KEY_NOTFOUND)) {
			res = util_key_add_node(list_keys(subtest),
						okey_params.key, NULL);
			if (res != ERR_CODE(PASSED))
				return res;

			res = util_key_update_node(list_keys(subtest),
						   okey_params.key, &key_data);
		}

		if (res != ERR_CODE(PASSED))
			return res;
	}

	json_object_put(restore_obj);

	return res;
}

int util_key_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, key_free_data, LIST_ID_TYPE_STRING);
}

int util_key_add_node(struct llist *keys, const char *key_name,
		      void *okey_params)
{
	int res = ERR_CODE(BAD_ARGS);

	struct key_data *data = NULL;

	if (!keys || !key_name)
		return res;

	data = calloc(1, sizeof(*data));
	if (!data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	data->okey_params = okey_params;

	res = util_list_add_node(keys, (uintptr_t)key_name, data);

	if (res != ERR_CODE(PASSED) && data)
		free(data);

	return res;
}

int util_key_update_node(struct llist *keys, const char *key_name,
			 struct key_data *key_data)
{
	int res = ERR_CODE(BAD_ARGS);

	struct key_data *data = NULL;

	if (!key_data || !keys)
		return res;

	res = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	data->identifier = key_data->identifier;

	if (!data->identifier) {
		/*
		 * Key is ephemeral. Save public key data to be able to use it
		 * later
		 */
		data->pub_key.data = key_data->pub_key.data;
		data->pub_key.length = key_data->pub_key.length;
	} else {
		data->pub_key.data = NULL;
	}

	return res;
}

int util_key_build_keys_list(char *dir_def_file, struct json_object *definition,
			     struct llist *keys)
{
	int res = ERR_CODE(PASSED);
	int err = ERR_CODE(PASSED);

	struct llist *files = NULL;

	res = util_list_init(&files, NULL, LIST_ID_TYPE_STRING);

	if (res == ERR_CODE(PASSED))
		res = build_keys_list(dir_def_file, definition, keys, files);

	err = util_list_clear(files);
	if (res == ERR_CODE(PASSED))
		res = err;

	return res;
}

int util_key_get_key_params(struct subtest_data *subtest, const char *key,
			    struct json_object **okey_params)
{
	int res = ERR_CODE(BAD_ARGS);
	const char *key_name = NULL;
	struct key_data *data = NULL;
	struct llist *keys = NULL;

	if (!subtest || !key || !okey_params)
		return res;

	keys = list_keys(subtest);
	if (!keys)
		return res;

	res = util_read_json_type(&key_name, key, t_string, subtest->params);
	if (res != ERR_CODE(PASSED))
		return res;

	res = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data) {
		*okey_params = NULL;
		return ERR_CODE(KEY_NOTFOUND);
	}

	*okey_params = data->okey_params;

	return res;
}

int util_key_save_keys_to_file(struct subtest_data *subtest)
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

	return save_keys_to_json_file(list_keys(subtest), filename);
}

int util_key_restore_keys_from_file(struct subtest_data *subtest)
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

	res = restore_keys_from_json_file(subtest, filename);

	if (res == ERR_CODE(PASSED))
		util_file_remove(filename);

	return res;
}
