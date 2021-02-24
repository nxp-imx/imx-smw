// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
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

void util_key_set_ops(struct keypair_ops *key_test, char *key_type)
{
	if (!key_test->keys) {
		key_test->public_data = NULL;
		key_test->public_length = NULL;
		key_test->private_data = NULL;
		key_test->private_length = NULL;
		key_test->modulus = NULL;
		key_test->modulus_length = NULL;
	} else if (key_type && !strcmp(key_type, RSA_KEY)) {
		key_test->public_data = &get_public_data_rsa;
		key_test->public_length = &get_public_length_rsa;
		key_test->private_data = &get_private_data_rsa;
		key_test->private_length = &get_private_length_rsa;
		key_test->modulus = &get_modulus_rsa;
		key_test->modulus_length = &get_modulus_length_rsa;
	} else {
		key_test->public_data = &get_public_data_gen;
		key_test->public_length = &get_public_length_gen;
		key_test->private_data = &get_private_data_gen;
		key_test->private_length = &get_private_length_gen;
		key_test->modulus = NULL;
		key_test->modulus_length = NULL;
	}
}

/**
 * util_key_get_node_info() - Get the key information saved in the key node
 * @node: Key node.
 * @key_test: Test keypair structure with operations to fill with saved data.
 *
 * Function fills the @key_test descriptor fields functions of the
 * key node fields saved.
 * If a descriptor field is already set, don't overwrite it.
 *
 */
static void util_key_get_node_info(struct key_identifier_node *node,
				   struct keypair_ops *key_test)
{
	if (!util_key_is_id_set(key_test))
		key_test->desc.id = node->key_identifier;

	if (!util_key_is_security_set(key_test))
		key_test->desc.security_size = node->security_size;
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
static int keypair_read(struct keypair_ops *key_test, json_object *params)
{
	int ret = ERR_CODE(PASSED);
	json_object *okey;

	if (!params || !key_test) {
		DBG_PRINT_BAD_ARGS(__func__);
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

int util_key_add_node(struct key_identifier_list **key_identifiers,
		      unsigned int id, struct keypair_ops *key_test)
{
	struct key_identifier_node *head = NULL;
	struct key_identifier_node *node;

	if (!key_test)
		return ERR_CODE(BAD_ARGS);

	node = malloc(sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	node->id = id;
	node->key_identifier = key_test->desc.id;
	node->security_size = key_test->desc.security_size;
	node->next = NULL;

	if (!*key_identifiers) {
		*key_identifiers = malloc(sizeof(struct key_identifier_list));
		if (!*key_identifiers) {
			free(node);
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		/* New key is the first of the list */
		(*key_identifiers)->head = node;
	} else {
		head = (*key_identifiers)->head;
		while (head->next)
			head = head->next;

		/* New key is the last of the list */
		head->next = node;
	}

	return ERR_CODE(PASSED);
}

void util_key_clear_list(struct key_identifier_list *key_identifiers)
{
	struct key_identifier_node *head = NULL;
	struct key_identifier_node *del = NULL;

	if (!key_identifiers)
		return;

	head = key_identifiers->head;

	while (head) {
		del = head;
		head = head->next;
		free(del);
	}

	free(key_identifiers);
}

int util_key_find_key_node(struct key_identifier_list *key_identifiers,
			   unsigned int id, struct keypair_ops *key_test)
{
	struct key_identifier_node *head = NULL;

	if (!key_identifiers || !key_test) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	head = key_identifiers->head;

	while (head) {
		if (head->id == id) {
			util_key_get_node_info(head, key_test);
			return ERR_CODE(PASSED);
		}

		head = head->next;
	}

	return ERR_CODE(KEY_NOTFOUND);
}

int util_key_desc_init(struct keypair_ops *key_test,
		       struct smw_keypair_buffer *key, char *key_type)
{
	struct smw_key_descriptor *desc;

	if (!key_test) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	desc->type_name = NULL;
	desc->security_size = KEY_SECURITY_NOT_SET;
	desc->id = KEY_ID_NOT_SET;
	desc->buffer = key;

	key_test->keys = key;

	/* Initialize the keypair buffer and operations */
	util_key_set_ops(key_test, key_type);

	if (key) {
		if (key_type && !strcmp(key_type, RSA_KEY)) {
			key->format_name = NULL;
			*key_public_data(key_test) = NULL;
			*key_public_length(key_test) = KEY_LENGTH_NOT_SET;
			*key_private_data(key_test) = NULL;
			*key_private_length(key_test) = KEY_LENGTH_NOT_SET;
			*key_modulus(key_test) = NULL;
			*key_modulus_length(key_test) = KEY_LENGTH_NOT_SET;
		} else {
			key->format_name = NULL;
			*key_public_data(key_test) = NULL;
			*key_public_length(key_test) = KEY_LENGTH_NOT_SET;
			*key_private_data(key_test) = NULL;
			*key_private_length(key_test) = KEY_LENGTH_NOT_SET;
		}
	}

	return ERR_CODE(PASSED);
}

int util_key_read_descriptor(struct keypair_ops *key_test, int *key_id,
			     json_object *params)
{
	int ret = ERR_CODE(PASSED);
	json_object *obj;
	struct smw_key_descriptor *desc;

	if (!params || !key_test || !key_id) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	desc = &key_test->desc;

	/* Read 'key_type' parameter if defined */
	if (json_object_object_get_ex(params, KEY_TYPE_OBJ, &obj))
		desc->type_name = json_object_get_string(obj);

	/* Read 'security_size' parameter if defined */
	if (json_object_object_get_ex(params, SEC_SIZE_OBJ, &obj))
		desc->security_size = json_object_get_int(obj);

	/* Read test 'key_id' value if defined */
	if (json_object_object_get_ex(params, KEY_ID_OBJ, &obj))
		*key_id = json_object_get_int(obj);

	/* Setup the key ops function of the key type */
	util_key_set_ops(key_test, (char *)desc->type_name);

	if (key_test->keys)
		ret = keypair_read(key_test, params);

	return ret;
}

int util_key_desc_set_key(struct keypair_ops *key_test,
			  struct smw_keypair_buffer *key)
{
	if (!key_test || !key) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	key_test->desc.buffer = key;
	key_test->keys = key;

	/* Initialize the keypair buffer and operations */
	util_key_set_ops(key_test, (char *)key_test->desc.type_name);

	if (key_test->desc.type_name &&
	    !strcmp(key_test->desc.type_name, RSA_KEY)) {
		key->format_name = NULL;
		*key_public_data(key_test) = NULL;
		*key_public_length(key_test) = KEY_LENGTH_NOT_SET;
		*key_private_data(key_test) = NULL;
		*key_private_length(key_test) = KEY_LENGTH_NOT_SET;
		*key_modulus(key_test) = NULL;
		*key_modulus_length(key_test) = KEY_LENGTH_NOT_SET;
	} else {
		key->format_name = NULL;
		*key_public_data(key_test) = NULL;
		*key_public_length(key_test) = KEY_LENGTH_NOT_SET;
		*key_private_data(key_test) = NULL;
		*key_private_length(key_test) = KEY_LENGTH_NOT_SET;
	}

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
}
