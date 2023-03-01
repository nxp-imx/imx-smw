/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */
#ifndef __UTIL_KEY_H__
#define __UTIL_KEY_H__

#include "types.h"

#include "util_list.h"

/**
 * struct key_data - Data of key linked list node.
 * @identifier: Key identifier assigned by SMW.
 * @pub_key: Public key data buffer structure. Used for ephemeral keys.
 * @okey_params: Pointer to the JSON-C object of key parameters.
 */
struct key_data {
	unsigned int identifier;
	struct tbuffer pub_key;
	struct json_object *okey_params;
};

/**
 * util_key_init() - Initialize the key list
 * @list: Pointer to linked list.
 *
 * Return:
 * PASSED                  - Success.
 * -BAD_ARG                - @list is NULL.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -FAILED                 - Failure
 */
int util_key_init(struct llist **list);

/**
 * util_key_add_node() - Add a new node in a key linked list.
 * @keys: Pointer to linked list.
 * @key_name: Key name.
 * @okey_params: Pointer to the JSON-C object of key parameters.
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -BAD_ARGS               - One of the argument is not correct.
 */
int util_key_add_node(struct llist *keys, const char *key_name,
		      void *okey_params);

/**
 * util_key_update_node() - Update a node in a key linked list.
 * @keys: Pointer to linked list.
 * @key_name: Key name.
 * @key_data: Key data to save
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -BAD_ARGS               - One of the argument is not correct.
 */
int util_key_update_node(struct llist *keys, const char *key_name,
			 struct key_data *key_data);

/**
 * util_key_build_keys_list() - Build the keys list.
 * @dir_def_file: Folder of the test definition file.
 * @definition: JSON-C object to be parsed.
 * @keys: Keys list.
 *
 * Return:
 * PASSED                  - Success.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 * -BAD_ARGS               - One of the argument is not correct.
 */
int util_key_build_keys_list(char *dir_def_file, struct json_object *definition,
			     struct llist *keys);

/**
 * util_key_get_key_params() - Get the key params.
 * @subtest: Subtest data.
 * @key_name: JSON-C key name.
 * @okey_params: Pointer to the JSON-C object of key parameters.
 *
 * Return:
 * PASSED                  - Success.
 * -KEY_NOTFOUND           - @id is not found.
 * -BAD_ARGS               - One of the argument is not correct.
 */
int util_key_get_key_params(struct subtest_data *subtest, const char *key_name,
			    struct json_object **okey_params);

/**
 * util_key_save_keys_to_file() - Save keys from a linked list in a file.
 * @subtest: Subtest data.
 *
 * The file where values are saved is a parameter from @params.
 *
 * Return:
 * PASSED                  - Success.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params.
 * -BAD_ARGS               - One of the arguments is bad.
 */
int util_key_save_keys_to_file(struct subtest_data *subtest);

/**
 * util_key_restore_keys_from_file() - Restore keys from a file to a linked list.
 * @subtest: Subtest data.
 *
 * The file where values are coming from is a parameter from @params.
 *
 * Return:
 * PASSED                  - Success.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params.
 * -API_STATUS_NOK         - SMW API Call return error
 * -BAD_ARGS               - One of the arguments is bad.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
int util_key_restore_keys_from_file(struct subtest_data *subtest);

#endif /* __UTIL_KEY_H__ */
