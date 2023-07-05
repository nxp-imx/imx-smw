// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include "types.h"
#include "util.h"
#include "util_key.h"

#include "key.h"

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
	int ret = ERR_CODE(INTERNAL);
	char *buf = NULL;
	unsigned int len = 0;
	unsigned int json_len = UINT_MAX;

	if (!key || !length)
		return ret;

	ret = util_read_json_buffer(&buf, &len, &json_len, okey);
	if (ret != ERR_CODE(PASSED)) {
		if (buf)
			free(buf);
		return ret;
	}

	/* If key buffer was already defined, overwrite it with the new definition. */
	if (*key)
		free(*key);

	*key = NULL;
	*length = 0;

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

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	if (json_len != UINT_MAX) {
		if (*key && json_len > len)
			return ERR_CODE(BAD_ARGS);

		*length = json_len;
	} else {
		*length = len;
	}

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
	struct json_object *okey = NULL;

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

static void key_free_key_buffers(struct keypair_ops *key_test)
{
	if (key_test && key_test->keys) {
		if (*key_public_data(key_test))
			free(*key_public_data(key_test));

		if (*key_private_data(key_test))
			free(*key_private_data(key_test));

		if (key_test->modulus && *key_modulus(key_test))
			free(*key_modulus(key_test));
	}
}

static int read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			   const char *key_name, struct llist *key_names)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *parent_key_name = NULL;
	struct smw_key_descriptor *desc = NULL;
	smw_key_type_t type_name = NULL;
	void *dummy = NULL;

	if (!key_test || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	ret = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	if (data->identifier) {
		desc->id = data->identifier;
		desc->security_size = 0;

		(void)smw_get_key_type_name(desc);
		(void)smw_get_security_size(desc);

		set_key_ops(key_test);

		return ERR_CODE(PASSED);
	}

	if (!data->okey_params)
		return ERR_CODE(PASSED);

	ret = util_read_json_type(&parent_key_name, KEY_NAME_OBJ, t_string,
				  data->okey_params);

	if (ret == ERR_CODE(PASSED) && parent_key_name) {
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

	/* Read 'type' parameter if defined */
	ret = util_read_json_type(&type_name, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (ret == ERR_CODE(PASSED)) {
		if (desc->type_name)
			key_free_key_buffers(key_test);

		desc->type_name = type_name;
	}

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

int key_desc_init(struct keypair_ops *key_test, struct smw_keypair_buffer *key)
{
	struct smw_key_descriptor *desc = NULL;

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

int key_read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			const char *key_name)
{
	int res = ERR_CODE(PASSED);
	int err = ERR_CODE(PASSED);

	struct llist *key_names = NULL;

	res = util_list_init(&key_names, NULL, LIST_ID_TYPE_STRING);

	if (res == ERR_CODE(PASSED))
		res = read_descriptor(keys, key_test, key_name, key_names);

	err = util_list_clear(key_names);
	if (res == ERR_CODE(PASSED))
		res = err;

	return res;
}

int key_desc_set_key(struct keypair_ops *key_test,
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

void key_free_key(struct keypair_ops *key_test)
{
	key_free_key_buffers(key_test);

	(void)key_desc_set_key(key_test, NULL);
}

void key_prepare_key_data(struct keypair_ops *key_test,
			  struct key_data *key_data)
{
	key_data->identifier = key_test->desc.id;
	if (key_test->keys) {
		key_data->pub_key.data = *key_test->public_data(key_test);
		key_data->pub_key.length = *key_test->public_length(key_test);
	}
}

/**
 * allocate_keys() - Allocate all fields present in keys structure
 * @keys: Pointer to structure to update
 *
 * Return:
 * PASSED			- Success
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failure
 */
static int allocate_keys(struct keys *keys)
{
	struct keypair_ops *keys_test = NULL;
	struct smw_key_descriptor **keys_desc = NULL;
	struct smw_keypair_buffer *keys_buffer = NULL;
	size_t alloc_size = 0;

	if (!keys->nb_keys)
		return ERR_CODE(INTERNAL);

	/* Allocate keypair ops array */
	if (MUL_OVERFLOW(keys->nb_keys, sizeof(*keys_test), &alloc_size))
		goto err;

	keys_test = calloc(1, alloc_size);
	if (!keys_test)
		goto err;

	/* Allocate keys descriptor array */
	if (MUL_OVERFLOW(keys->nb_keys, sizeof(*keys_desc), &alloc_size))
		goto err;

	keys_desc = calloc(1, alloc_size);
	if (!keys_desc)
		goto err;

	/* Allocate keys buffer array */
	if (MUL_OVERFLOW(keys->nb_keys, sizeof(*keys_buffer), &alloc_size))
		goto err;

	keys_buffer = calloc(1, alloc_size);
	if (!keys_buffer)
		goto err;

	keys->keys_test = keys_test;
	keys->keys_desc = keys_desc;
	keys->keys_buffer = keys_buffer;

	return ERR_CODE(PASSED);

err:
	if (keys_test)
		free(keys_test);

	if (keys_desc)
		free(keys_desc);

	return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
}

void free_keys(struct keys *keys)
{
	unsigned int i = 0;

	if (keys->keys_desc) {
		free(keys->keys_desc);
		keys->keys_desc = NULL;
	}

	for (; i < keys->nb_keys; i++)
		key_free_key(&keys->keys_test[i]);

	if (keys->keys_buffer) {
		free(keys->keys_buffer);
		keys->keys_buffer = NULL;
	}

	if (keys->keys_test) {
		free(keys->keys_test);
		keys->keys_test = NULL;
	}
}

int key_read_descriptors(struct subtest_data *subtest, const char *key,
			 unsigned int *nb_keys,
			 struct smw_key_descriptor ***keys_desc,
			 struct keys *keys)

{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int i = 0;
	struct keypair_ops *key_test = NULL;
	struct json_object *okey_name = NULL;
	struct json_object *obj = NULL;
	const char *key_name = NULL;

	res = util_read_json_type(&key_name, key, t_string, subtest->params);
	if (res == ERR_CODE(PASSED)) {
		*nb_keys = 1;
	} else if (res == ERR_CODE(BAD_PARAM_TYPE)) {
		res = util_read_json_type(&okey_name, key, t_array,
					  subtest->params);
		if (res != ERR_CODE(PASSED))
			return res;

		if (SET_OVERFLOW(json_object_array_length(okey_name), *nb_keys))
			return ERR_CODE(INTERNAL);
	} else {
		return res;
	}

	/*
	 * If this is API test number of keys = 0, need to allocate
	 * at least one key, else test is failed for other reason.
	 */
	keys->nb_keys = *nb_keys;
	if (is_api_test(subtest) && keys->nb_keys == 0)
		keys->nb_keys = 1;

	res = allocate_keys(keys);
	if (res != ERR_CODE(PASSED))
		return res;

	if (!keys->keys_test || !keys->keys_desc || !keys->keys_buffer)
		return ERR_CODE(INTERNAL);

	for (i = 0; i < keys->nb_keys; i++) {
		key_test = &keys->keys_test[i];

		/* Initialize key descriptor */
		res = key_desc_init(key_test, &keys->keys_buffer[i]);
		if (res != ERR_CODE(PASSED))
			return res;

		if (okey_name) {
			obj = json_object_array_get_idx(okey_name, i);
			if (obj)
				key_name = json_object_get_string(obj);
		}

		if (key_name) {
			res = key_read_descriptor(list_keys(subtest), key_test,
						  key_name);

			if (res != ERR_CODE(PASSED))
				return res;

			if (key_is_id_set(key_test))
				key_free_key(key_test);
		}

		if (!key_is_id_set(key_test) && !is_api_test(subtest) &&
		    (!key_is_type_set(key_test) ||
		     !key_is_security_set(key_test) ||
		     !key_is_private_key_defined(key_test))) {
			DBG_PRINT_MISS_PARAM("Key description");
			return ERR_CODE(MISSING_PARAMS);
		}

		key_name = NULL;

		keys->keys_desc[i] = &key_test->desc;
	}

	*keys_desc = keys->keys_desc;

	return ERR_CODE(PASSED);
}
