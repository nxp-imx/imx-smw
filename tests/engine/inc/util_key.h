/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */
#ifndef __UTIL_KEY_H__
#define __UTIL_KEY_H__

#include <assert.h>
#include <limits.h>
#include <json_object.h>

#include "smw_keymgr.h"

#include "util_list.h"

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
 * struct keypair_ops - Test keypair with operations
 * @desc: SMW key descriptor
 * @keys: Pointer to the SMW keypair buffer
 * @public_data: Get the @keys' public data reference
 * @public_length: Get the @keys' public length reference
 * @private_data: Get the @keys' private data reference
 * @private_length: Get the @keys' private length reference
 * @modulus: Get the @key's modulus data reference
 * @modulus_length: Get the @key's modulus length reference
 *
 * This structure is internal to the test enabling to handle any
 * SMW keypair object referenced in the `struct smw_keypair_buffer`.
 * Operation function pointers are setup when calling util_key_desc_init()
 * or util_key_desc_set_key() functions.
 */
struct keypair_ops {
	struct smw_key_descriptor desc;
	struct smw_keypair_buffer *keys;
	unsigned char **(*public_data)(struct keypair_ops *this);
	unsigned int *(*public_length)(struct keypair_ops *this);
	unsigned char **(*private_data)(struct keypair_ops *this);
	unsigned int *(*private_length)(struct keypair_ops *this);
	unsigned char **(*modulus)(struct keypair_ops *this);
	unsigned int *(*modulus_length)(struct keypair_ops *this);
};

#define key_public_data(this)                                                  \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->public_data);                                    \
		_this->public_data(_this);                                     \
	})

#define key_public_length(this)                                                \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->public_length);                                  \
		_this->public_length(_this);                                   \
	})

#define key_private_data(this)                                                 \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->private_data);                                   \
		_this->private_data(_this);                                    \
	})

#define key_private_length(this)                                               \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->private_length);                                 \
		_this->private_length(_this);                                  \
	})

#define key_modulus(this)                                                      \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->modulus);                                        \
		_this->modulus(_this);                                         \
	})

#define key_modulus_length(this)                                               \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->modulus_length);                                 \
		_this->modulus_length(_this);                                  \
	})

/**
 * struct key_identifier_data - Data of key identifier linked list node.
 * @key_identifier: Key identifier assigned by SMW.
 * @security_size: Key security size.
 * @pub_key: Public key data buffer structure. Used for ephemeral keys.
 */
struct key_identifier_data {
	unsigned long long key_identifier;
	unsigned int security_size;
	struct tbuffer pub_key;
};

/**
 * util_key_is_type_set() - Return if key type is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_type_set(struct keypair_ops *key_test)
{
	return !!key_test->desc.type_name;
}

/**
 * util_key_is_id_set() - Return if key id is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_id_set(struct keypair_ops *key_test)
{
	return (key_test->desc.id != KEY_ID_NOT_SET);
}

/**
 * util_key_is_security_set() - Return if security size defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_security_set(struct keypair_ops *key_test)
{
	return (key_test->desc.security_size != KEY_SECURITY_NOT_SET);
}

/**
 * util_key_is_public_len_set() - Return if public key length is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_public_len_set(struct keypair_ops *key_test)
{
	return (*key_public_length(key_test) != KEY_LENGTH_NOT_SET);
}

/**
 * util_key_is_private_len_set() - Return if private key length is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_private_len_set(struct keypair_ops *key_test)
{
	return (*key_private_length(key_test) != KEY_LENGTH_NOT_SET);
}

/**
 * util_key_is_modulus_len_set() - Return if modulus length is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_modulus_len_set(struct keypair_ops *key_test)
{
	return (*key_modulus_length(key_test) != KEY_LENGTH_NOT_SET);
}

/**
 * util_key_is_public_key_defined() - Return if public key buffer is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_public_key_defined(struct keypair_ops *key_test)
{
	return (*key_public_length(key_test) != KEY_LENGTH_NOT_SET) &&
	       *key_public_data(key_test);
}

/**
 * util_key_is_private_key_defined() - Return if private key buffer is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int util_key_is_private_key_defined(struct keypair_ops *key_test)
{
	return (*key_private_length(key_test) != KEY_LENGTH_NOT_SET) &&
	       *key_private_data(key_test);
}

/**
 * util_key_is_modulus() - Return if modulus buffer is supported.
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not supported, otherwise true
 */
static inline int util_key_is_modulus(struct keypair_ops *key_test)
{
	return key_test->modulus_length && key_test->modulus;
}

/**
 * util_key_add_node() - Add a new node in a key identifier linked list.
 * @key_identifiers: Pointer to linked list.
 * @id: Local ID of the key identifier. Comes from test definition file.
 * @key_test: Test keypair structure with operations to save
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the argument is not correct.
 */
int util_key_add_node(struct llist **key_identifiers, unsigned int id,
		      struct keypair_ops *key_test);

/**
 * util_key_find_key_node() - Search a key identifier node.
 * @key_identifiers: Key identifier linked list where the research is done.
 * @id: Id of the key identifier.
 * @key_test: Test keypair structure with operations to fill
 *
 * Return:
 * PASSED        - Success.
 * -KEY_NOTFOUND - @id is not found.
 * -BAD_ARGS     - One of the argument is not correct.
 */
int util_key_find_key_node(struct llist *key_identifiers, unsigned int id,
			   struct keypair_ops *key_test);

/**
 * util_key_desc_init() - Initialize SMW key descriptor fields
 * @key_test: Test keypair structure with operations
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
int util_key_desc_init(struct keypair_ops *key_test,
		       struct smw_keypair_buffer *key);

/**
 * util_key_read_descriptor() - Read the key descriptor definition
 * @key_test: Test keypair structure with operations
 * @key_id: Test application key id
 * @key_idx: Key index if @params contains multiple keys
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
int util_key_read_descriptor(struct keypair_ops *key_test, int *key_id,
			     unsigned int key_idx, json_object *params);

/**
 * util_key_desc_set_key() - Set a SMW keypair to the key descriptor
 * @key_test: Test keypair structure with operations
 * @key: SMW keypair buffer
 *
 * Setup the test keypair to use the @key SMW keypair buffer.
 * Initialize the @key with default unset value.
 *
 * Return:
 * PASSED    - Success
 * -BAD_ARGS - Bad function argument
 */
int util_key_desc_set_key(struct keypair_ops *key_test,
			  struct smw_keypair_buffer *key);

/**
 * util_key_set_ops() - Set a SMW keypair to the key descriptor
 * @key_test: Test keypair structure with operations
 *
 * Setup the test keypair operations.
 *
 * Return:
 * None.
 */
void util_key_set_ops(struct keypair_ops *key_test);

/**
 * util_key_free_key() - Free test keypair buffer
 * @key_test: Test keypair structure with operations
 */
void util_key_free_key(struct keypair_ops *key_test);

#endif /* __UTIL_KEY_H__ */
