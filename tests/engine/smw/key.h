/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2025 NXP
 */
#ifndef __KEY_H__
#define __KEY_H__

#include <assert.h>
#include <limits.h>

#include <smw_keymgr.h>

#include "util_key.h"

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
 * @modulus: Get the @key's modulus reference
 * @modulus_length: Get the @key's modulus length reference
 * @public_exponent: Get the @key's s public exponent reference
 * @public_exponent_length: Get the @key's public exponent length reference
 *
 * This structure is internal to the test enabling to handle any
 * SMW keypair object referenced in the `struct smw_keypair_buffer`.
 * Operation function pointers are setup when calling key_desc_init()
 * or key_desc_set_key() functions.
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
	unsigned char **(*public_exponent)(struct keypair_ops *this);
	unsigned int *(*public_exponent_length)(struct keypair_ops *this);
};

/**
 * struct keys - Group of structures representing keys
 * @nb_keys: Number of keys
 * @keys_test: Pointer to an array of test keypair structures
 * @keys_desc: Pointer to an array of SMW key descriptor pointers
 * @keys_buffer: Pointer to an array of key buffer
 */
struct keys {
	unsigned int nb_keys;
	struct keypair_ops *keys_test;
	struct smw_key_descriptor **keys_desc;
	struct smw_keypair_buffer *keys_buffer;
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

#define key_public_exponent(this)                                              \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->public_exponent);                                \
		_this->public_exponent(_this);                                 \
	})

#define key_public_exponent_length(this)                                       \
	({                                                                     \
		__typeof__(this) _this = (this);                               \
		assert(_this);                                                 \
		assert(_this->public_exponent_length);                         \
		_this->public_exponent_length(_this);                          \
	})

/**
 * key_is_type_set() - Return if key type is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_type_set(struct keypair_ops *key_test)
{
	return key_test->desc.type_name != SMW_KEY_TYPE_NAME_NONE;
}

/**
 * key_is_id_set() - Return if key id is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_id_set(struct keypair_ops *key_test)
{
	return (key_test->desc.id != KEY_ID_NOT_SET);
}

/**
 * key_is_security_set() - Return if security size defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_security_set(struct keypair_ops *key_test)
{
	return (key_test->desc.security_size != KEY_SECURITY_NOT_SET);
}

/**
 * key_is_public_len_set() - Return if public key length is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_public_len_set(struct keypair_ops *key_test)
{
	return (*key_public_length(key_test) != KEY_LENGTH_NOT_SET);
}

/**
 * key_is_private_len_set() - Return if private key length is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_private_len_set(struct keypair_ops *key_test)
{
	return (*key_private_length(key_test) != KEY_LENGTH_NOT_SET);
}

/**
 * key_is_modulus_len_set() - Return if modulus length is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_modulus_len_set(struct keypair_ops *key_test)
{
	return (*key_modulus_length(key_test) != KEY_LENGTH_NOT_SET);
}

/**
 * key_is_public_key_defined() - Return if public key buffer is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_public_key_defined(struct keypair_ops *key_test)
{
	return (*key_public_length(key_test) != KEY_LENGTH_NOT_SET) &&
	       *key_public_data(key_test);
}

/**
 * key_is_private_key_defined() - Return if private key buffer is defined
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not set, otherwise true
 */
static inline int key_is_private_key_defined(struct keypair_ops *key_test)
{
	return (*key_private_length(key_test) != KEY_LENGTH_NOT_SET) &&
	       *key_private_data(key_test);
}

/**
 * key_is_modulus() - Return if modulus buffer is supported.
 * @key_test: Test keypair structure with operations
 *
 * Return:
 * false if not supported, otherwise true
 */
static inline int key_is_modulus(struct keypair_ops *key_test)
{
	return key_test->modulus_length && key_test->modulus;
}

/**
 * key_get_type_name() - Get the key type name
 * @string: Name as a string
 *
 * Return:
 * Key type name.
 */
smw_key_type_t key_get_type_name(const char *string);

/**
 * key_get_format_name() - Get the key format name
 * @string: Name as a string
 *
 * Return:
 * Key format name.
 */
smw_key_format_t key_get_format_name(const char *string);

/**
 * key_desc_init() - Initialize SMW key descriptor fields
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
int key_desc_init(struct keypair_ops *key_test, struct smw_keypair_buffer *key);

/**
 * set_key_ops() - Set a SMW keypair to the key descriptor
 * @key_test: Test keypair structure with operations
 *
 * Setup the test keypair operations.
 *
 * Return:
 * None.
 */
void set_key_ops(struct keypair_ops *key_test);

/**
 * key_read_descriptor() - Read the key descriptor definition
 * @keys: Keys list.
 * @key_test: Test keypair structure with operations.
 * @key_name: Key name.
 *
 * Read the test definition to extract SMW key descriptor fields.
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
int key_read_descriptor(struct llist *keys, struct keypair_ops *key_test,
			const char *key_name);

/**
 * key_desc_set_key() - Set a SMW keypair to the key descriptor
 * @key_test: Test keypair structure with operations.
 * @key: SMW keypair buffer.
 *
 * Setup the test keypair to use the @key SMW keypair buffer.
 * Initialize the @key with default unset value.
 *
 * Return:
 * PASSED    - Success
 * -BAD_ARGS - Bad function argument
 */
int key_desc_set_key(struct keypair_ops *key_test,
		     struct smw_keypair_buffer *key);

/**
 * key_free_key() - Free test keypair buffer
 * @key_test: Test keypair structure with operations
 */
void key_free_key(struct keypair_ops *key_test);

/**
 * key_prepare_key_data() - Fill key data structure
 * @key_test: Test keypair structure with operations
 * @key_data: Key data to save
 */
void key_prepare_key_data(struct keypair_ops *key_test,
			  struct key_data *key_data);

/**
 * free_keys() - Free all fields present in keys structure
 * @keys: Pointer to keys structure
 *
 * Return:
 * none
 */
void free_keys(struct keys *keys);

/**
 * key_read_descriptors() - Read the key descriptors definition
 * @subtest: Subtest data
 * @key: Key value to read
 * @nb_keys: Pointer to the number of keys
 * @keys_desc: Address of the pointer to the array of public key descriptors
 *             pointer.
 * @keys: Pointer to structure to update
 *
 * This function reads the keys description present in the test definition file
 * and set the keys structure.
 *
 * Return:
 * PASSED		- Success
 * -API_STATUS_NOK      - SMW API Call return error
 * -MISSING_PARAMS	- Mandatory parameters are missing
 * -INTERNAL		- Internal error
 * Error code from allocate_keys
 * Error code from key_desc_init
 * Error code from key_read_descriptor
 */
int key_read_descriptors(struct subtest_data *subtest, const char *key,
			 unsigned int *nb_keys,
			 struct smw_key_descriptor ***keys_desc,
			 struct keys *keys);

/**
 * algorithm_callback() - Set algorithm
 * @user_data: Pointer to the algorithm.
 * @params: List of algorithm parameters as strings.
 * @n_params: Number of algorithm parameters.
 *
 * Return:
 * None.
 */
void algorithm_callback(void *user_data, const char *params[], size_t n_params);

/**
 * usage_callback() - Set key usage
 * @user_data: Pointer to the usage bitmap.
 * @attributes: List of attributes as strings.
 * @n_attributes: Number of attributes.
 *
 * Return:
 * None.
 */
void usage_callback(void *user_data, const char *attributes[],
		    size_t n_attributes);

/**
 * attributes_callback() - Set attributes
 * @user_data: Pointer to the storage attributes bitmap.
 * @attributes: List of attributes as strings.
 * @n_attributes: Number of attributes.
 *
 * Return:
 * None.
 */
void attributes_callback(void *user_data, const char *attributes[],
			 size_t n_attributes);

/**
 * key_read_attributes() - Read the key attributes
 * @params: json-c parameters.
 * @attributes: Address where the attributes are written.
 *
 * This function reads the key attributes present in the test definition file.
 *
 * Return:
 * PASSED		- Success
 * Error code from util_attr_read_attributes
 */
int key_read_attributes(struct json_object *params,
			struct smw_key_attributes *attributes);

#endif /* __KEY_H__ */
