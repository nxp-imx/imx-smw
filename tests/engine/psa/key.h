/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __KEY_H__
#define __KEY_H__

#include <stddef.h>
#include <stdint.h>

#include <psa/crypto.h>

#include "util_key.h"

/**
 * struct keypair_psa - Test keypair
 * @attributes: PSA key attributes.
 * @data: Buffer where the key data has been written.
 * @data_length: Length of @data.
 *
 * This structure is internal to the test enabling to handle any
 * PSA keypair object.
 */
struct keypair_psa {
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

#endif /* __KEY_H__ */
