/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_KEY_H__
#define __UTIL_KEY_H__

#include <limits.h>
#include <json_object.h>

#include "smw_keymgr.h"

/*
 * Key format values
 */
#define KEY_FORMAT_BASE64    "BASE64"
#define KEY_FORMAT_HEX	     "HEX"
#define KEY_FORMAT_UNDEFINED "UNDEFINED"

/*
 * Definition of the key descriptor fields not set
 * and associated macros
 */
#define KEY_SECURITY_NOT_SET UINT_MAX
#define KEY_ID_NOT_SET	     0
#define KEY_LENGTH_NOT_SET   0

/**
 * struct key_identifier_node - Node of key identifier linked list.
 * @id: Local ID of the key identifier. Comes from test definition file.
 * @key_identifier: Key identifier assigned by SMW.
 * @security_size: Key security size.
 * @next: Pointer to next node.
 */
struct key_identifier_node {
	unsigned int id;
	unsigned long long key_identifier;
	unsigned int security_size;
	struct key_identifier_node *next;
};

/**
 * struct key_identifier_list - Linked list to save keys identifiers.
 * @head: Pointer to the head of the linked list
 */
struct key_identifier_list {
	struct key_identifier_node *head;
};

/**
 * util_key_is_id_set() - Return if key id is defined
 * @desc: SMW key descriptor
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_id_set(struct smw_key_descriptor *desc)
{
	return (desc->id != KEY_ID_NOT_SET);
}

/**
 * util_key_is_security_set() - Return if security size defined
 * @desc: SMW key descriptor
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_security_set(struct smw_key_descriptor *desc)
{
	return (desc->security_size != KEY_SECURITY_NOT_SET);
}

/**
 * util_key_is_public_len_set() - Return if public key length is defined
 * @key: SMW keypair buffer
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_public_len_set(struct smw_keypair_buffer *key)
{
	return (key->public_length != KEY_LENGTH_NOT_SET);
}

/**
 * util_key_is_private_len_set() - Return if private key length is defined
 * @key: SMW keypair buffer
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_private_len_set(struct smw_keypair_buffer *key)
{
	return (key->private_length != KEY_LENGTH_NOT_SET);
}

/**
 * util_key_add_node() - Add a new node in a key identifier linked list.
 * @key_identifiers: Pointer to linked list.
 * @id: Local ID of the key identifier. Comes from test definition file.
 * @key_desc: SMW key descriptor containing key information to save
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the argument is not correct.
 */
int util_key_add_node(struct key_identifier_list **key_identifiers,
		      unsigned int id, struct smw_key_descriptor *key_desc);

/**
 * util_key_clear_list() - Clear key identifier linked list.
 * @key_identifiers: Key identifier linked list to clear.
 *
 * Return:
 * none
 */
void util_key_clear_list(struct key_identifier_list *key_identifiers);

/**
 * util_key_find_key_node() - Search a key identifier node.
 * @key_identifiers: Key identifier linked list where the research is done.
 * @id: Id of the key identifier.
 * @key_desc: SMW key descriptor to fill with key information saved
 *
 * Return:
 * PASSED        - Success.
 * -KEY_NOTFOUND - @id is not found.
 * -BAD_ARGS     - One of the argument is not correct.
 */
int util_key_find_key_node(struct key_identifier_list *key_identifiers,
			   unsigned int id,
			   struct smw_key_descriptor *key_desc);

/**
 * util_key_desc_init() - Initialize SMW key descriptor fields
 * @desc: SMW key descriptor
 * @key: SMW keypair buffer (can be NULL)
 *
 * Initialize key descriptor fields with default unset value.
 * Set the key descriptor key buffer with the @key pointer.
 * If @key is given initialize it with default unset value.
 *
 * Return:
 * PASSED    - Success
 * -BAD_ARGS - Bad function argument
 */
int util_key_desc_init(struct smw_key_descriptor *desc,
		       struct smw_keypair_buffer *key);

/**
 * util_key_read_descriptor() - Read the key descriptor definition
 * @desc: SMW Key descriptor to setup
 * @key_id: Test application key id
 * @params: json-c object
 *
 * Read the test definition @param to extract SMW key descriptor field.
 * Caller is in charge of checking if mandatory fields are set or not.
 * If the @desc->buffer is set, read the keys definition (format, public
 * and private keys if defined).
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int util_key_read_descriptor(struct smw_key_descriptor *desc, int *key_id,
			     json_object *params);

#endif /* __UTIL_KEY_H__ */
