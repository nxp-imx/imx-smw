// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */
#include <stdlib.h>
#include <string.h>

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
 * get_key_node_info() - Get the key information saved in the key node
 * @data: Key node data.
 * @key_test: Test keypair structure with operations to fill with saved data.
 *
 * Function fills the @key_test descriptor fields functions of the
 * key node fields saved.
 * If a descriptor field is already set, don't overwrite it.
 *
 */
static void get_key_node_info(struct key_identifier_data *data,
			      struct keypair_ops *key_test)
{
	if (!util_key_is_id_set(key_test))
		key_test->desc.id = data->key_identifier;

	if (!util_key_is_security_set(key_test))
		key_test->desc.security_size = data->security_size;
}

/**
 * read_key() - Read the key buffer from json-c object
 * @key: Key buffer to return
 * @length: Length of the key
 * @format: Key format of json-c buffer
 * @okey: json-c object
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
		    const char *format, json_object *okey)
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
 * @key_idx: Key index if @params contains multiple keys
 * @params: json-c object
 *
 * Read and set the key format, public key buffer and private key buffer.
 * Key buffer is defined by a string or an array of string.
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
static int keypair_read(struct keypair_ops *key_test, unsigned int key_idx,
			json_object *params)
{
	int ret = ERR_CODE(PASSED);
	unsigned int nb_keys = 1;
	json_object *okey;
	json_object *nb_keys_obj;

	if (!params || !key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (json_object_object_get_ex(params, KEY_FORMAT_OBJ, &okey))
		key_test->keys->format_name = json_object_get_string(okey);

	if (json_object_object_get_ex(params, PUB_KEY_OBJ, &okey)) {
		ret = read_key(key_public_data(key_test),
			       key_public_length(key_test),
			       key_test->keys->format_name, okey);

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	if (json_object_object_get_ex(params, PRIV_KEY_OBJ, &okey)) {
		/*
		 * Private key parameter could be an array of multiple private
		 * key definition. i.e: an array of private key array
		 */
		if (json_object_object_get_ex(params, NB_KEYS_OBJ,
					      &nb_keys_obj))
			nb_keys = json_object_get_int(nb_keys_obj);

		/* Case where multiple keys are defined as key buffer */
		if (nb_keys > 1 &&
		    json_object_get_type(okey) == json_type_array) {
			if (key_idx >= json_object_array_length(okey))
				return ERR_CODE(BAD_PARAM_TYPE);

			okey = json_object_array_get_idx(okey, key_idx);
		}

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
	struct key_identifier_data *key_identifier_data = data;

	if (key_identifier_data && key_identifier_data->pub_key.data)
		free(key_identifier_data->pub_key.data);
}

static int get_key_id(int *key_id, unsigned int key_idx, json_object *params)
{
	int err;
	struct json_object *obj = NULL;
	struct json_object *oval = NULL;
	unsigned int nb_elem = 1;

	if (!key_id)
		return ERR_CODE(PASSED);

	/*
	 * Key id format possible are:
	 * - id
	 * - [id]
	 * - [id 1, id 2]
	 */
	err = util_read_json_type(&obj, KEY_ID_OBJ, t_ints, params);
	if (err != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (err == ERR_CODE(VALUE_NOTFOUND))
			err = ERR_CODE(PASSED);
		return err;
	}

	switch (json_object_get_type(obj)) {
	case json_type_int:
		if (key_idx < nb_elem)
			*key_id = json_object_get_int(obj);
		break;

	case json_type_array:
		nb_elem = json_object_array_length(obj);
		if (key_idx >= nb_elem)
			break;

		oval = json_object_array_get_idx(obj, key_idx);
		if (json_object_get_type(oval) != json_type_int) {
			DBG_PRINT("%s must be array of integer", KEY_ID_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}
		*key_id = json_object_get_int(oval);
		break;

	default:
		return ERR_CODE(FAILED);
	}

	return ERR_CODE(PASSED);
}

int util_key_init(struct llist **list)
{
	if (!list)
		return ERR_CODE(BAD_ARGS);

	return util_list_init(list, util_key_free_data);
}

int util_key_add_node(struct llist *key_identifiers, unsigned int id,
		      struct keypair_ops *key_test)
{
	int res;

	struct key_identifier_data *data;

	if (!key_test || !key_identifiers)
		return ERR_CODE(BAD_ARGS);

	data = malloc(sizeof(*data));
	if (!data) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	data->key_identifier = key_test->desc.id;
	data->security_size = key_test->desc.security_size;

	if (!data->key_identifier) {
		/*
		 * Key is ephemeral. Save public key data to be able to use it
		 * later
		 */
		data->pub_key.data = *key_test->public_data(key_test);
		data->pub_key.length = *key_test->public_length(key_test);
	} else {
		data->pub_key.data = NULL;
	}

	res = util_list_add_node(key_identifiers, id, data);

	if (res != ERR_CODE(PASSED) && data)
		free(data);

	return res;
}

int util_key_find_key_node(struct llist *key_identifiers, unsigned int id,
			   struct keypair_ops *key_test)
{
	int res;
	struct key_identifier_data *data;

	if (!key_identifiers || !key_test)
		return ERR_CODE(BAD_ARGS);

	res = util_list_find_node(key_identifiers, id, (void **)&data);
	if (res == ERR_CODE(PASSED) && !data)
		res = ERR_CODE(KEY_NOTFOUND);

	if (res == ERR_CODE(PASSED))
		get_key_node_info(data, key_test);

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

int util_key_read_descriptor(struct keypair_ops *key_test, int *key_id,
			     unsigned int key_idx, json_object *params)
{
	int ret = ERR_CODE(PASSED);
	struct smw_key_descriptor *desc;

	if (!params || !key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	/* Read 'key_type' parameter if defined */
	ret = util_read_json_type(&desc->type_name, KEY_TYPE_OBJ, t_string,
				  params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'security_size' parameter if defined */
	ret = util_read_json_type(&desc->security_size, SEC_SIZE_OBJ, t_int,
				  params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read test 'key_id' value if defined */
	ret = get_key_id(key_id, key_idx, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	/* Setup the key ops function of the key type */
	set_key_ops(key_test);

	if (key_test->keys)
		ret = keypair_read(key_test, key_idx, params);

	return ret;
}

int util_key_desc_set_key(struct keypair_ops *key_test,
			  struct smw_keypair_buffer *key)
{
	if (!key_test || !key) {
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

	util_key_desc_init(key_test, NULL);
}
