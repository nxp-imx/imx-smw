/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2025 NXP
 */
#ifndef __KEY_H__
#define __KEY_H__

#include <stddef.h>
#include <stdint.h>

#include <psa/crypto.h>

#include "util_key.h"

/**
 * struct keypair_psa - Test keypair
 * @name: Name of the key in the JSON test definition.
 * @attributes: PSA key attributes.
 * @data: Buffer where the key data has been written.
 * @data_length: Length of @data.
 *
 * This structure is internal to the test enabling to handle any
 * PSA keypair object.
 */
struct keypair_psa {
	const char *name;
	psa_key_attributes_t attributes;
	uint8_t *data;
	size_t data_length;
};

/**
 * key_desc_init_psa() - Initialize PSA key descriptor fields
 * @key_test: Test keypair structure
 *
 * Initialize key descriptor fields with default unset value.
 *
 * Return:
 * PASSED    - Success
 * -BAD_ARGS - Bad function argument
 */
int key_desc_init_psa(struct keypair_psa *key_test);

/**
 * key_read_descriptor_psa() - Set the PSA key attributes
 * @keys: Keys list.
 * @key_test: Test keypair structure.
 * @key_name: Key name.
 *
 * Read the test definition to extract PSA key ID, attributes and buffer.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int key_read_descriptor_psa(struct llist *keys, struct keypair_psa *key_test,
			    const char *key_name);

/**
 * key_prepare_key_data_psa() - Fill key data structure
 * @key_test: Test keypair structure
 * @key_data: Key data to save
 */
void key_prepare_key_data_psa(struct keypair_psa *key_test,
			      struct key_data *key_data);

/**
 * algorithm_callback_psa() - Set algorithm
 * @user_data: Pointer to the algorithm.
 * @params: List of algorithm parameters as strings.
 * @n_params: Number of algorithm parameters.
 *
 * Return:
 * None.
 */
void algorithm_callback_psa(void *user_data, const char *params[],
			    size_t n_params);

/**
 * key_read_descriptors_psa() - Read multiple PSA keys in a single step
 * @subtest: Subtest data.
 * @key: Key value to read.
 * @nb_keys: Pointer to the number of keys.
 * @keys: Address of the pointer to the output keys list.
 *
 * This function reads the keys descriptions present in the test definition file
 * and set the keys structure.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL                - Number of keys is too large.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int key_read_descriptors_psa(struct subtest_data *subtest, const char *key,
			     unsigned int *nb_keys, struct keypair_psa **keys);

#endif /* __KEY_H__ */
