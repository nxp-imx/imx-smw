/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_KEY_ASYM_MAPPINGS_H
#define CLI_KEY_ASYM_MAPPINGS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "backend.h"

struct asym_key_type_mapping {
	const char *name;
	uint32_t value;	     /* opaque backend key type value */
	uint32_t fixed_size; /* 0 = variable size */
	uint64_t curve;	     /* opaque backend curve value */
};

struct asym_algo_mapping {
	const char *name;
	uint64_t value; /* opaque backend algorithm/mode/hash value */
};

/* Key type mappings */
const struct asym_key_type_mapping *get_asym_key_type_mappings(void);
size_t get_asym_key_type_mappings_count(void);

/* Categorized key type getters */
const struct asym_key_type_mapping *get_rsa_sig_key_types(void);
size_t get_rsa_sig_key_types_count(void);

const struct asym_key_type_mapping *get_ecdsa_sig_key_types(void);
size_t get_ecdsa_sig_key_types_count(void);

const struct asym_key_type_mapping *get_eddsa_sig_key_types(void);
size_t get_eddsa_sig_key_types_count(void);

const struct asym_key_type_mapping *get_dsa_sig_key_types(void);
size_t get_dsa_sig_key_types_count(void);

const struct asym_key_type_mapping *get_rsa_enc_key_types(void);
size_t get_rsa_enc_key_types_count(void);

const struct asym_key_type_mapping *get_key_exchange_key_types(void);
size_t get_key_exchange_key_types_count(void);

/* Algorithm component mappings */
const struct asym_algo_mapping *get_sign_mode_mappings(void);
size_t get_sign_mode_mappings_count(void);

const struct asym_algo_mapping *get_encrypt_mode_mappings(void);
size_t get_encrypt_mode_mappings_count(void);

const struct asym_algo_mapping *get_sign_hash_algo_mappings(void);
size_t get_sign_hash_algo_mappings_count(void);

const struct asym_algo_mapping *get_eddsa_algo_mappings(void);
size_t get_eddsa_algo_mappings_count(void);

const struct asym_algo_mapping *get_kdf_algo_mappings(void);
size_t get_kdf_algo_mappings_count(void);
const struct asym_algo_mapping *get_tls_algo_mappings(void);
size_t get_tls_algo_mappings_count(void);

/* Parse and conversion helpers */

int parse_asym_key_type(const char *str, uint32_t *fixed_size, uint32_t *value);
const char *asym_key_type_to_string(uint32_t value);
uint64_t parse_sign_mode(const char *str);
uint64_t parse_encrypt_mode(const char *str);
uint64_t parse_sign_hash(const char *str);
uint64_t get_asym_curve(uint32_t value);

/* Category check helpers */
bool is_asym_rsa_sig_type(const char *type_str);
bool is_asym_rsa_enc_type(const char *type_str);
bool is_asym_ecdsa_sig_type(const char *type_str);
bool is_asym_eddsa_sig_type(const char *type_str);
bool is_asym_dsa_sig_type(const char *type_str);
bool is_asym_key_ex_type(const char *type_str);

#endif /* CLI_KEY_ASYM_MAPPINGS_H */
