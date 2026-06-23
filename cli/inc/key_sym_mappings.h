/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_KEY_SYM_MAPPINGS_H
#define CLI_KEY_SYM_MAPPINGS_H

#include <stddef.h>
#include <stdint.h>

#include "backend.h"

struct key_type_mapping {
	const char *name;
	uint32_t value;
};

struct algo_mapping {
	const char *name;
	uint32_t value;
};

/* Key type mappings */
const struct key_type_mapping *get_key_type_mappings(void);
size_t get_key_type_mappings_count(void);

/* Cipher algorithm (mode) mappings */
const struct algo_mapping *get_cipher_algo_mappings(void);
size_t get_cipher_algo_mappings_count(void);

/* AEAD algorithm (mode) mappings */
const struct algo_mapping *get_aead_algo_mappings(void);
size_t get_aead_algo_mappings_count(void);

/* HMAC: hash algorithm mappings (SHA256, SHA512 …) */
const struct algo_mapping *get_hmac_hash_algo_mappings(void);
size_t get_hmac_hash_algo_mappings_count(void);

/* CMAC: block-cipher mode mappings */
const struct algo_mapping *get_cmac_algo_mappings(void);
size_t get_cmac_algo_mappings_count(void);

/* Categorized key type name arrays */
const char **get_cipher_key_types(size_t *count);
const char **get_aead_key_types(size_t *count);
const char **get_cmac_key_types(size_t *count);

/* Parse and conversion helpers */
int parse_key_type(const char *str, uint32_t *value);
const char *key_type_to_string(uint32_t value);
int parse_single_algorithm(const char *algo_str, uint32_t key_type_value,
			   uint32_t *algo_value);

#endif /* CLI_KEY_SYM_MAPPINGS_H */
