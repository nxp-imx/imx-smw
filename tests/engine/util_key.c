// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */
#include <stdlib.h>
#include <string.h>
#include <json.h>

#include "util.h"
#include "util_key.h"

static struct smw_keypair_gen *get_keypair_gen(struct keypair_ops *this)
{
	assert(this && this->keys);
	return &this->keys->gen;
}

static unsigned char **get_public_data_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->public_data;
}

static unsigned int *get_public_length_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->public_length;
}

static unsigned char **get_private_data_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->private_data;
}

static unsigned int *get_private_length_gen(struct keypair_ops *this)
{
	struct smw_keypair_gen *key = get_keypair_gen(this);

	return &key->private_length;
}

static struct smw_keypair_rsa *get_keypair_rsa(struct keypair_ops *this)
{
	assert(this && this->keys);
	return &this->keys->rsa;
}

static unsigned char **get_public_data_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->public_data;
}

static unsigned int *get_public_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->public_length;
}

static unsigned char **get_private_data_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->private_data;
}

static unsigned int *get_private_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->private_length;
}

static unsigned char **get_modulus_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->modulus;
}

static unsigned int *get_modulus_length_rsa(struct keypair_ops *this)
{
	struct smw_keypair_rsa *key = get_keypair_rsa(this);

	return &key->modulus_length;
}

/**
 * set_key_ops() - Set a SMW keypair to the key descriptor
 * @key_test: Test keypair structure with operations
 *
 * Setup the test keypair operations.
 *
 * Return:
 * None.
 */
static void set_key_ops(struct keypair_ops *key_test)
{
	if (!key_test->keys) {
		key_test->public_data = NULL;
		key_test->public_length = NULL;
		key_test->private_data = NULL;
		key_test->private_length = NULL;
		key_test->modulus = NULL;
		key_test->modulus_length = NULL;

		return;
	}

	if (key_test->desc.type_name &&
	    !strcmp(key_test->desc.type_name, RSA_KEY)) {
		key_test->public_data = &get_public_data_rsa;
		key_test->public_length = &get_public_length_rsa;
		key_test->private_data = &get_private_data_rsa;
		key_test->private_length = &get_private_length_rsa;
		key_test->modulus = &get_modulus_rsa;
		key_test->modulus_length = &get_modulus_length_rsa;

		*key_modulus(key_test) = NULL;
		*key_modulus_length(key_test) = KEY_LENGTH_NOT_SET;
	} else {
		key_test->public_data = &get_public_data_gen;
		key_test->public_length = &get_public_length_gen;
		key_test->private_data = &get_private_data_gen;
		key_test->private_length = &get_private_length_gen;
		key_test->modulus = NULL;
		key_test->modulus_length = NULL;
	}

	key_test->keys->format_name = NULL;
	*key_public_data(key_test) = NULL;
	*key_public_length(key_test) = KEY_LENGTH_NOT_SET;
	*key_private_data(key_test) = NULL;
	*key_private_length(key_test) = KEY_LENGTH_NOT_SET;
}

/**
 * read_key() - Read the key buffer from json-c object
 * @key: Key buffer to return
 * @length: Length of the key
 * @format: Key format of json-c buffer
 * @okey: Key json-c object
 *
 * Function read the json-c key object if defined.
 * Function allocates the key buffer caller must free it.
 *
 * Return:
 * PASSED                   - Success
 * -FAILED                  - Function failure
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -BAD_ARGS                - Bad function argument
 */
static int read_key(unsigned char **key, unsigned int *length,
		    const char *format, struct json_object *okey)
{
	int ret = ERR_CODE(PASSED);
	char *buf = NULL;
	unsigned int len = 0;
	unsigned int json_len = UINT_MAX;

	ret = util_read_json_buffer(&buf, &len, &json_len, okey);
	if (ret != ERR_CODE(PASSED)) {
		if (buf)
			free(buf);
		return ret;
	}

	/* Either test definition specify:
	 * - length != 0 but no data
	 * - length = 0 but data
	 * - no length but data
	 * - length and data
	 */
	if (!buf || (format && !strcmp(format, KEY_FORMAT_BASE64))) {
		*key = (unsigned char *)buf;
	} else {
		ret = util_string_to_hex(buf, key, &len);
		/*
		 * Buffer can be freed because a new one has been
		 * allocated to convert the string to hex
		 */
		free(buf);
	}

	if (json_len != UINT_MAX)
		*length = json_len;
	else
		*length = len;

	return ret;
}

/**
 * keypair_read() - Read the public and private key definition
 * @key_test: Test keypair structure with operations
 * @params: json-c object
 *
 * Read and set the key format, public key buffer and private key buffer.
 * Key buffer is defined by a string.
 * The public and private data buffer of the @key SMW buffer object are
 * allocated by this function but must be freed by caller if function
 * succeed.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
static int keypair_read(struct keypair_ops *key_test,
			struct json_object *params)
{
	int ret = ERR_CODE(PASSED);
	struct json_object *okey;

	if (!params || !key_test || !key_test->keys) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (json_object_object_get_ex(params, FORMAT_OBJ, &okey))
		key_test->keys->format_name = json_object_get_string(okey);

	if (json_object_object_get_ex(params, PUB_KEY_OBJ, &okey)) {
		ret = read_key(key_public_data(key_test),
			       key_public_length(key_test),
			       key_test->keys->format_name, okey);

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	if (json_object_object_get_ex(params, PRIV_KEY_OBJ, &okey)) {
		ret = read_key(key_private_data(key_test),
			       key_private_length(key_test),
			       key_test->keys->format_name, okey);

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	if (json_object_object_get_ex(params, MODULUS_OBJ, &okey))
		ret = read_key(key_modulus(key_test),
			       key_modulus_length(key_test),
			       key_test->keys->format_name, okey);

	return ret;
}

static void util_key_free_data(void *data)
{
	struct key_data *key_data = data;

	if (key_data) {
		if (key_data->pub_key.data)
			free(key_data->pub_key.data);

		free(data);
	}
}

static int read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			   const char *key_name, struct llist *key_names)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *parent_key_name = NULL;
	struct smw_key_descriptor *desc;
	void *dummy = NULL;

	if (!key_test || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	if (data->identifier) {
		key_test->desc.id = data->identifier;
		key_test->desc.security_size = 0;

		(void)smw_get_key_type_name(&key_test->desc);
		(void)smw_get_security_size(&key_test->desc);

		return ERR_CODE(PASSED);
	}

	if (!data->okey_params)
		return ERR_CODE(PASSED);

	ret = util_read_json_type(&parent_key_name, KEY_NAME_OBJ, t_string,
				  data->okey_params);

	if (ret == ERR_CODE(PASSED)) {
		ret = util_list_find_node(key_names, (uintptr_t)parent_key_name,
					  &dummy);
		if (ret != ERR_CODE(PASSED))
			return ret;

		if (dummy) {
			DBG_PRINT("Error: nested key definition (%s, %s)",
				  parent_key_name, key_name);
			return ERR_CODE(BAD_ARGS);
		}

		/*
		 * Add a node in list key_names with id set to parent_key_name.
		 * No data is stored by the node. But data pointer must be different to NULL
		 * in order to detect later if the node is found in the list.
		 * Data pointer is not freed when the list is cleared
		 * because the method to free the data is set to NULL
		 * when list is initialized.
		 */
		ret = util_list_add_node(key_names, (uintptr_t)parent_key_name,
					 (void *)1);
		if (ret != ERR_CODE(PASSED))
			return ret;

		ret = read_descriptor(keys, key_test, parent_key_name,
				      key_names);
		if (ret != ERR_CODE(PASSED))
			return ret;
	} else if (ret != ERR_CODE(VALUE_NOTFOUND)) {
		return ret;
	}

	desc = &key_test->desc;

	/* Read 'type' parameter if defined */
	ret = util_read_json_type(&desc->type_name, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'security_size' parameter if defined */
	ret = util_read_json_type(&desc->security_size, SEC_SIZE_OBJ, t_int,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'id' parameter if defined */
	ret = util_read_json_type(&desc->id, ID_OBJ, t_int, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Setup the key ops function of the key type */
	set_key_ops(key_test);

	if (key_test->keys) {
		ret = keypair_read(key_test, data->okey_params);
		if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
			return ret;
	}

	return ERR_CODE(PASSED);
}

static int util_key_register_keys(struct json_object *okeys, struct llist *keys)
{
	int res;
	struct json_object_iter okey_params;
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

	return ERR_CODE(PASSED);
}

static int build_keys_list(char *dir_def_file, struct json_object *definition,
			   struct llist *keys, struct llist *files)
{
	int res;
	struct json_object *okeys = NULL;
	struct json_object *odef = NULL;
	struct json_object_iter obj;
	char *def_file = NULL;
	void *dummy = NULL;

	if (!definition || !keys)
		return ERR_CODE(BAD_ARGS);

	res = util_read_json_type(&okeys, KEYS_OBJ, t_object, definition);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		return res;

	if (res == ERR_CODE(PASSED)) {
		res = util_key_register_keys(okeys, keys);
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
		if (!strcmp(obj.key, KEYS_OBJ))
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

int util_key_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, util_key_free_data, LIST_ID_TYPE_STRING);
}

int util_key_add_node(struct llist *keys, const char *key_name,
		      void *okey_params)
{
	int res = ERR_CODE(BAD_ARGS);

	struct key_data *data;

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
			 struct keypair_ops *key_test)
{
	int res = ERR_CODE(BAD_ARGS);

	struct key_data *data = NULL;

	if (!key_test || !keys)
		return res;

	res = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	data->identifier = key_test->desc.id;

	if (!data->identifier && key_test->keys) {
		/*
		 * Key is ephemeral. Save public key data to be able to use it
		 * later
		 */
		data->pub_key.data = *key_test->public_data(key_test);
		data->pub_key.length = *key_test->public_length(key_test);
	} else {
		data->pub_key.data = NULL;
	}

	return res;
}

int util_key_desc_init(struct keypair_ops *key_test,
		       struct smw_keypair_buffer *key)
{
	struct smw_key_descriptor *desc;

	if (!key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	desc->type_name = NULL;
	desc->security_size = KEY_SECURITY_NOT_SET;
	desc->id = KEY_ID_NOT_SET;
	desc->buffer = key;

	key_test->keys = key;

	/* Initialize the keypair buffer and operations */
	set_key_ops(key_test);

	return ERR_CODE(PASSED);
}

int util_key_read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			     const char *key_name)
{
	int res, err;

	struct llist *key_names = NULL;

	res = util_list_init(&key_names, NULL, LIST_ID_TYPE_STRING);

	if (res == ERR_CODE(PASSED))
		res = read_descriptor(keys, key_test, key_name, key_names);

	err = util_list_clear(key_names);
	if (res == ERR_CODE(PASSED))
		res = err;

	return res;
}

int util_key_desc_set_key(struct keypair_ops *key_test,
			  struct smw_keypair_buffer *key)
{
	if (!key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	key_test->desc.buffer = key;
	key_test->keys = key;

	/* Initialize the keypair buffer and operations */
	set_key_ops(key_test);

	return ERR_CODE(PASSED);
}

void util_key_free_key(struct keypair_ops *key_test)
{
	if (key_test && key_test->keys) {
		if (*key_public_data(key_test))
			free(*key_public_data(key_test));

		if (*key_private_data(key_test))
			free(*key_private_data(key_test));

		if (key_test->modulus && *key_modulus(key_test))
			free(*key_modulus(key_test));
	}

	(void)util_key_desc_set_key(key_test, NULL);
}

int util_key_build_keys_list(char *dir_def_file, struct json_object *definition,
			     struct llist *keys)
{
	int res, err;

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
	struct llist *keys;

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
