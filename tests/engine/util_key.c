// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "util_key.h"

/**
 * util_key_get_node_info() - Get the key information saved in the key node
 * @node: Key node.
 * @key_desc: SMW key descriptor to fill with key information saved.
 *
 * Function fills the @key_desc fields functions of the key node fields
 * saved.
 * If a @key_desc field is already set, don't overwrite it.
 *
 */
static void util_key_get_node_info(struct key_identifier_node *node,
				   struct smw_key_descriptor *key_desc)
{
	if (!util_key_is_id_set(key_desc))
		key_desc->id = node->key_identifier;

	if (!util_key_is_security_set(key_desc))
		key_desc->security_size = node->security_size;
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
	if (ret != ERR_CODE(PASSED))
		return ret;

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
 * @key: SMW Key buffer parameter to setup
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
static int keypair_read(struct smw_keypair_buffer *key, json_object *params)
{
	int ret;
	json_object *okey;

	if (!params || !key) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	if (json_object_object_get_ex(params, KEY_FORMAT_OBJ, &okey))
		key->format_name = json_object_get_string(okey);

	if (json_object_object_get_ex(params, PUB_KEY_OBJ, &okey)) {
		ret = read_key(&key->public_data, &key->public_length,
			       key->format_name, okey);

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	if (json_object_object_get_ex(params, PRIV_KEY_OBJ, &okey))
		ret = read_key(&key->private_data, &key->private_length,
			       key->format_name, okey);

	return ret;
}

int util_key_add_node(struct key_identifier_list **key_identifiers,
		      unsigned int id, struct smw_key_descriptor *key_desc)
{
	struct key_identifier_node *head = NULL;
	struct key_identifier_node *node;

	if (!key_desc)
		return ERR_CODE(BAD_ARGS);

	node = malloc(sizeof(*node));
	if (!node) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	node->id = id;
	node->key_identifier = key_desc->id;
	node->security_size = key_desc->security_size;
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
			   unsigned int id, struct smw_key_descriptor *key_desc)
{
	struct key_identifier_node *head = NULL;

	if (!key_identifiers || !key_desc) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	head = key_identifiers->head;

	while (head) {
		if (head->id == id) {
			util_key_get_node_info(head, key_desc);
			return ERR_CODE(PASSED);
		}

		head = head->next;
	}

	return ERR_CODE(KEY_NOTFOUND);
}

int util_key_desc_init(struct smw_key_descriptor *desc,
		       struct smw_keypair_buffer *key)
{
	if (!desc) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	desc->type_name = NULL;
	desc->security_size = KEY_SECURITY_NOT_SET;
	desc->id = KEY_ID_NOT_SET;
	desc->buffer = key;

	if (key) {
		key->format_name = NULL;
		key->public_data = NULL;
		key->public_length = KEY_LENGTH_NOT_SET;
		key->private_data = NULL;
		key->private_length = KEY_LENGTH_NOT_SET;
	}

	return ERR_CODE(PASSED);
}

int util_key_read_descriptor(struct smw_key_descriptor *desc, int *key_id,
			     json_object *params)
{
	int ret = ERR_CODE(PASSED);
	json_object *obj;

	if (!params || !desc || !key_id) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	/* Read 'key_type' parameter if defined */
	if (json_object_object_get_ex(params, KEY_TYPE_OBJ, &obj))
		desc->type_name = json_object_get_string(obj);

	/* Read 'security_size' parameter if defined */
	if (json_object_object_get_ex(params, SEC_SIZE_OBJ, &obj))
		desc->security_size = json_object_get_int(obj);

	/* Read test 'key_id' value if defined */
	if (json_object_object_get_ex(params, KEY_ID_OBJ, &obj))
		*key_id = json_object_get_int(obj);

	if (desc->buffer)
		ret = keypair_read(desc->buffer, params);

	return ret;
}
