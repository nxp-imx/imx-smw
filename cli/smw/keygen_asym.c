// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <smw_config.h>
#include <smw_crypto.h>
#include <smw_keymgr.h>
#include <smw_status.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "keygen_common.h"
#include "key_asym_mappings.h"
#include "logger.h"
#include "parser_keygen_asym.h"
#include "utils.h"

#define USAGE_STR_LEN	  64
#define USAGE_STR_MAX_LEN 256
#define ALGO_STR_MAX_LEN  1024

#define SMW_EDDSA_SIGN(curve, hash, param)                                     \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_EDDSA(curve, hash, param)
#define SMW_RSA_ENCR(mode, hash)                                               \
	SMW_ATTR_ALGO_ASYMMETRIC_ENCRYPTION_RSA(mode, hash)
#define SMW_RSA_SIGN(mode, hash, salt)                                         \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(mode, hash, salt)
#define SMW_ECDSA_SIGN(curve, hash)                                            \
	SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(curve, hash)
#define SMW_DSA_SIGN(hash) SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_DSA(hash)

/**
 * @brief Split algorithm string into tokens
 *
 * @param algo_str Algorithm string to split (e.g., "PSS-SHA256")
 * @param tokens Array to store token pointers (caller must free)
 * @param max_tokens Maximum number of tokens to extract
 * @return Number of tokens extracted, or -1 on error
 */
static int tokenize_algo(const char *algo_str, char **tokens, int max_tokens)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	int count = 0;

	if (!algo_str || !tokens || max_tokens <= 0)
		return -1;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return -1;

	token = strtok_r(algo_copy, "-", &saveptr);
	while (token && count < max_tokens) {
		tokens[count] = strdup(token);
		if (!tokens[count]) {
			while (count > 0)
				free(tokens[--count]);
			free(algo_copy);
			return -1;
		}
		count++;
		token = strtok_r(NULL, "-", &saveptr);
	}

	free(algo_copy);
	return count;
}

/**
 * @brief Free token array
 *
 * @param tokens Array of token pointers to free
 * @param count Number of tokens in array
 */
static void free_tokens(char **tokens, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (tokens[i])
			free(tokens[i]);
	}
}

/**
 * @brief Parse a key derivation algorithm string
 *
 * @param algo_str Algorithm string
 */
static smw_attr_algo_t parse_kdf_algo(const char *algo_str)
{
	char *algo_copy = NULL;
	char *kdf_str = NULL;
	char *hash_str = NULL;
	char *saveptr = NULL;
	unsigned long long hash = 0;
	smw_attr_algo_t res = SMW_ATTR_ALGO_NONE;
	const struct asym_algo_mapping *table = NULL;
	size_t count = 0;
	size_t i = 0;

	if (!algo_str)
		return SMW_ATTR_ALGO_NONE;

	/*
	 * First try exact match (no hash component) in both
	 * TLS and KDF tables — handles ECDH, DH, etc.
	 * Must add CLASS=KEY_DERIVATION explicitly.
	 */
	table = get_tls_algo_mappings();
	count = get_tls_algo_mappings_count();
	for (; i < count; i++) {
		if (table[i].name && !strcasecmp(algo_str, table[i].name))
			return SMW_ATTR_NAME(CLASS, KEY_DERIVATION) |
			       SMW_ATTR_NAME(CURVE, ANY) |
			       SMW_ATTR_VALUE(ALGO, table[i].value);
	}

	table = get_kdf_algo_mappings();
	count = get_kdf_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (table[i].name && !strcasecmp(algo_str, table[i].name))
			return SMW_ATTR_NAME(CLASS, KEY_DERIVATION) |
			       SMW_ATTR_NAME(CURVE, ANY) |
			       SMW_ATTR_VALUE(ALGO, table[i].value);
	}

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return SMW_ATTR_ALGO_NONE;

	kdf_str = strtok_r(algo_copy, "-", &saveptr);
	hash_str = saveptr;

	if (!kdf_str || !hash_str)
		goto cleanup;

	hash = parse_sign_hash(hash_str);
	if (!hash)
		goto cleanup;

	/* Check TLS table */
	table = get_tls_algo_mappings();
	count = get_tls_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (!table[i].name)
			continue;
		if (!strcasecmp(kdf_str, table[i].name)) {
			res = SMW_ATTR_NAME(CLASS, KEY_DERIVATION) |
			      SMW_ATTR_VALUE(ALGO, table[i].value) |
			      SMW_ATTR_NAME(CURVE, ANY) |
			      SMW_ATTR_VALUE(HASH, hash);
			goto cleanup;
		}
	}

	/* Check KDF table */
	table = get_kdf_algo_mappings();
	count = get_kdf_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (!table[i].name)
			continue;
		if (!strcasecmp(kdf_str, table[i].name)) {
			res = SMW_ATTR_NAME(CLASS, KEY_DERIVATION) |
			      SMW_ATTR_VALUE(ALGO, table[i].value) |
			      SMW_ATTR_NAME(CURVE, ANY) |
			      SMW_ATTR_VALUE(HASH, hash);
			goto cleanup;
		}
	}

cleanup:
	free(algo_copy);
	return res;
}

/**
 * @brief Parse algorithm string dynamically using generated tables
 *
 * @param algo_str Algorithm string to parse
 * @param key_type Key type string (needed for ECDSA/EdDSA to determine curve)
 */
static smw_attr_algo_t parse_smw_single_algo(const char *algo_str,
					     const char *key_type)
{
	char *tokens[4] = { NULL };
	int token_count = 0;
	unsigned long long base_algo = 0;
	unsigned long long mode = 0;
	unsigned long long hash = 0;
	unsigned long long curve = SMW_ATTR_CURVE_NONE;
	smw_attr_algo_t res = SMW_ATTR_ALGO_NONE;
	const struct asym_algo_mapping *eddsa_algos = NULL;
	size_t eddsa_algo_count = 0;
	size_t i = 0;
	uint32_t dummy_size = 0;
	uint32_t key_type_value = 0;
	const char *key_type_str = NULL;

	if (!algo_str)
		return SMW_ATTR_ALGO_NONE;

	if (parse_asym_key_type(key_type, &dummy_size, &key_type_value) != 0) {
		LOG_ERROR("Invalid key type: %s", key_type);
		return SMW_ATTR_ALGO_NONE;
	}

	key_type_str = asym_key_type_to_string(key_type_value);

	/*
	 * For dual-use types (e.g. SECP_R1 can do ECDSA or HKDF/TLS13),
	 * try KDF/TLS parsing first — checks both tls and kdf tables,
	 * bare and hash-based. If it succeeds, use it.
	 */
	res = parse_kdf_algo(algo_str);
	if (res != SMW_ATTR_ALGO_NONE)
		return res;

	eddsa_algos = get_eddsa_algo_mappings();
	eddsa_algo_count = get_eddsa_algo_mappings_count();

	token_count = tokenize_algo(algo_str, tokens, 4);
	if (token_count < 0)
		return SMW_ATTR_ALGO_NONE;

	if (is_asym_rsa_sig_type(key_type_str) ||
	    is_asym_rsa_enc_type(key_type_str)) {
		base_algo = SMW_ATTR_ALGO_RSA;
	} else if (is_asym_dsa_sig_type(key_type_str)) {
		base_algo = SMW_ATTR_ALGO_DSA;
	} else if (is_asym_ecdsa_sig_type(key_type_str)) {
		if (token_count >= 1 && !strcasecmp(tokens[0], "ECDSA")) {
			base_algo = SMW_ATTR_ALGO_ECDSA;
			curve = SMW_ATTR_CURVE_ANY;
		} else {
			LOG_ERROR("ECDSA algorithm must start with 'ECDSA-'");
			goto cleanup;
		}
	} else if (is_asym_eddsa_sig_type(key_type_str)) {
		for (i = 0; i < eddsa_algo_count; i++) {
			if (!eddsa_algos[i].name)
				continue;
			if (!strcasecmp(algo_str, eddsa_algos[i].name)) {
				curve = get_asym_curve(key_type_value);
				if (curve == SMW_ATTR_CURVE_ANY) {
					LOG_ERROR("Invalid curve for type: %s",
						  key_type);
					goto cleanup;
				}
				res = SMW_EDDSA_SIGN(curve, SMW_ATTR_HASH_NONE,
						     eddsa_algos[i].value);
				goto cleanup;
			}
		}
		LOG_ERROR("Unknown EdDSA algorithm: %s", algo_str);
		goto cleanup;
	} else {
		LOG_ERROR("Unknown key type for algorithm parsing: %s",
			  key_type);
		goto cleanup;
	}

	if (base_algo == SMW_ATTR_ALGO_RSA) {
		if (token_count == 1) {
			mode = parse_encrypt_mode(tokens[0]);
			if (!mode) {
				LOG_ERROR("Unknown RSA mode: %s", tokens[0]);
				goto cleanup;
			}
			res = SMW_RSA_ENCR(mode, SMW_ATTR_HASH_NONE);
			goto cleanup;
		}

		if (token_count < 2) {
			LOG_ERROR("Invalid RSA algorithm format: %s", algo_str);
			goto cleanup;
		}

		mode = parse_sign_mode(tokens[0]);
		if (!mode)
			mode = parse_encrypt_mode(tokens[0]);
		if (!mode) {
			LOG_ERROR("Unknown RSA mode: %s", tokens[0]);
			goto cleanup;
		}

		if (!strcasecmp(tokens[1], "CRYPT")) {
			res = SMW_RSA_ENCR(mode, SMW_ATTR_HASH_NONE);
		} else {
			hash = parse_sign_hash(tokens[1]);
			if (!hash) {
				LOG_ERROR("Unknown hash algorithm: %s",
					  tokens[1]);
				goto cleanup;
			}
			if (mode == SMW_ATTR_MODE_OAEP)
				res = SMW_RSA_ENCR(mode, hash);
			else
				res = SMW_RSA_SIGN(mode, hash, 0);
		}
	} else if (base_algo == SMW_ATTR_ALGO_DSA) {
		if (token_count != 1) {
			LOG_ERROR("Invalid DSA algorithm format: %s", algo_str);
			goto cleanup;
		}
		hash = parse_sign_hash(tokens[0]);
		if (!hash) {
			LOG_ERROR("Unknown hash algorithm: %s", tokens[0]);
			goto cleanup;
		}
		res = SMW_DSA_SIGN(hash);
	} else if (base_algo == SMW_ATTR_ALGO_ECDSA) {
		if (token_count != 2) {
			LOG_ERROR("Invalid ECDSA algorithm format: %s",
				  algo_str);
			goto cleanup;
		}
		hash = parse_sign_hash(tokens[1]);
		if (!hash) {
			LOG_ERROR("Unknown hash algorithm: %s", tokens[1]);
			goto cleanup;
		}
		res = SMW_ECDSA_SIGN(curve, hash);
	}

cleanup:
	free_tokens(tokens, token_count);
	return res;
}

/**
 * @brief Parse multiple permitted algorithms from comma-separated string
 *
 * @param algo_str Comma-separated algorithm list
 * @param key_type Key type for context (needed for ECDSA/EdDSA)
 * @param permitted_algo Output combined permitted algorithm value
 */
static int parse_smw_multi_algos(const char *algo_str, const char *key_type,
				 smw_attr_algo_t *permitted_algo)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	smw_attr_algo_t first_algo = 0;
	smw_attr_algo_t single_algo = 0;
	smw_attr_algo_t mode_and_hash = 0;
	int count = 0;
	int ret = -1;

	if (!algo_str || !permitted_algo)
		return -1;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return -1;

	token = strtok_r(algo_copy, ",", &saveptr);
	while (token) {
		while (*token == ' ')
			token++;

		single_algo = parse_smw_single_algo(token, key_type);

		if (single_algo == SMW_ATTR_ALGO_NONE) {
			LOG_ERROR("Unknown algorithm: %s", token);
			goto cleanup;
		}

		if (!count)
			first_algo = single_algo;
		else
			mode_and_hash |= single_algo ^ first_algo;

		count++;
		token = strtok_r(NULL, ",", &saveptr);
	}

	*permitted_algo = first_algo;

	if (count > 1) {
		if (SMW_ATTR_GET_MODE(mode_and_hash))
			*permitted_algo = SMW_ATTR_SET_MODE(*permitted_algo,
							    SMW_ATTR_MODE_ANY);

		if (SMW_ATTR_GET_HASH(mode_and_hash))
			*permitted_algo = SMW_ATTR_SET_HASH(*permitted_algo,
							    SMW_ATTR_HASH_ANY);

		if (SMW_ATTR_GET_CURVE(mode_and_hash))
			*permitted_algo =
				SMW_ATTR_SET_CLEAR_VALUE(*permitted_algo, CURVE,
							 SMW_ATTR_CURVE_ANY);
	}

	ret = 0;

cleanup:
	free(algo_copy);
	return ret;
}

/**
 * @brief Append an algorithm name to an output buffer
 *
 * @param name        Algorithm name string to append
 * @param buffer      Output string buffer
 * @param buffer_size Total size of @buffer in bytes
 * @param written     Pointer to current write offset in @buffer (updated on success)
 * @param first       Pointer to flag indicating first entry
 */
static void append_algo_name(const char *name, char *buffer, size_t buffer_size,
			     size_t *written, bool *first)
{
	int ret;

	if (*written >= buffer_size)
		return;

	ret = snprintf(buffer + *written, buffer_size - *written, "%s%s",
		       *first ? "" : ", ", name);

	if (ret > 0 && (size_t)ret < buffer_size - *written) {
		*written += ret;
		*first = false;
	}
}

/**
 * @brief Check and append RSA algorithms to output buffer
 */
static void check_rsa_algo(smw_attr_algo_t permitted_algo,
			   const struct asym_algo_mapping *sign_modes,
			   size_t sign_mode_count,
			   const struct asym_algo_mapping *encrypt_modes,
			   size_t encrypt_mode_count,
			   const struct asym_algo_mapping *sign_hashes,
			   size_t hash_count, char *buffer, size_t buffer_size,
			   size_t *written, bool *first)
{
	size_t i, j;
	char algo_name[USAGE_STR_LEN];
	smw_attr_algo_t stored_class = SMW_ATTR_GET_CLASS(permitted_algo);
	smw_attr_algo_t stored_algo = SMW_ATTR_GET_ALGO(permitted_algo);
	smw_attr_algo_t stored_mode = SMW_ATTR_GET_MODE(permitted_algo);
	smw_attr_algo_t stored_hash = SMW_ATTR_GET_HASH(permitted_algo);

	if (stored_algo != SMW_ATTR_ALGO_RSA)
		return;

	if (stored_class == SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE) {
		for (i = 0; i < sign_mode_count; i++) {
			if (stored_mode != sign_modes[i].value &&
			    stored_mode != SMW_ATTR_MODE_ANY)
				continue;
			for (j = 0; j < hash_count; j++) {
				if (stored_hash == sign_hashes[j].value ||
				    stored_hash == SMW_ATTR_HASH_ANY) {
					SNPRINTF(algo_name, sizeof(algo_name),
						 "%s-%s", sign_modes[i].name,
						 sign_hashes[j].name);
					append_algo_name(algo_name, buffer,
							 buffer_size, written,
							 first);
				}
			}
		}
	} else if (stored_class == SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION) {
		for (i = 0; i < encrypt_mode_count; i++) {
			if (stored_mode != encrypt_modes[i].value &&
			    stored_mode != SMW_ATTR_MODE_ANY)
				continue;
			if (encrypt_modes[i].value == SMW_ATTR_MODE_OAEP) {
				for (j = 0; j < hash_count; j++) {
					if (stored_hash ==
						    sign_hashes[j].value ||
					    stored_hash == SMW_ATTR_HASH_ANY) {
						SNPRINTF(algo_name,
							 sizeof(algo_name),
							 "OAEP-%s",
							 sign_hashes[j].name);
						append_algo_name(algo_name,
								 buffer,
								 buffer_size,
								 written,
								 first);
					}
				}
			} else {
				SNPRINTF(algo_name, sizeof(algo_name),
					 "%s-CRYPT", encrypt_modes[i].name);
				append_algo_name(algo_name, buffer, buffer_size,
						 written, first);
			}
		}
	}
}

/**
 * @brief Check and append ECDSA algorithms to output buffer
 */
static void check_ecdsa_algo(smw_attr_algo_t permitted_algo,
			     const struct asym_algo_mapping *sign_hashes,
			     size_t hash_count, char *buffer,
			     size_t buffer_size, size_t *written, bool *first)
{
	size_t j;
	char algo_name[USAGE_STR_LEN];
	smw_attr_algo_t stored_class = SMW_ATTR_GET_CLASS(permitted_algo);
	smw_attr_algo_t stored_algo = SMW_ATTR_GET_ALGO(permitted_algo);
	smw_attr_algo_t stored_hash = SMW_ATTR_GET_HASH(permitted_algo);

	if (stored_class != SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE ||
	    stored_algo != SMW_ATTR_ALGO_ECDSA)
		return;

	for (j = 0; j < hash_count; j++) {
		if (stored_hash == sign_hashes[j].value ||
		    stored_hash == SMW_ATTR_HASH_ANY) {
			SNPRINTF(algo_name, sizeof(algo_name), "ECDSA-%s",
				 sign_hashes[j].name);
			append_algo_name(algo_name, buffer, buffer_size,
					 written, first);
		}
	}
}

/**
 * @brief Check and append EdDSA algorithms to output buffer
 */
static void check_eddsa_algo(smw_attr_algo_t permitted_algo,
			     const struct asym_algo_mapping *eddsa_algos,
			     size_t eddsa_algo_count, char *buffer,
			     size_t buffer_size, size_t *written, bool *first)
{
	size_t i;
	smw_attr_algo_t stored_class = SMW_ATTR_GET_CLASS(permitted_algo);
	smw_attr_algo_t stored_algo = SMW_ATTR_GET_ALGO(permitted_algo);

	if (stored_class != SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE ||
	    stored_algo != SMW_ATTR_ALGO_EDDSA)
		return;

	for (i = 0; i < eddsa_algo_count; i++) {
		append_algo_name(eddsa_algos[i].name, buffer, buffer_size,
				 written, first);
	}
}

/**
 * @brief Check and append DSA algorithms to output buffer
 */
static void check_dsa_algo(smw_attr_algo_t permitted_algo,
			   const struct asym_algo_mapping *sign_hashes,
			   size_t hash_count, char *buffer, size_t buffer_size,
			   size_t *written, bool *first)
{
	size_t j;
	smw_attr_algo_t stored_class = SMW_ATTR_GET_CLASS(permitted_algo);
	smw_attr_algo_t stored_algo = SMW_ATTR_GET_ALGO(permitted_algo);
	smw_attr_algo_t stored_hash = SMW_ATTR_GET_HASH(permitted_algo);

	if (stored_class != SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE ||
	    stored_algo != SMW_ATTR_ALGO_DSA)
		return;

	for (j = 0; j < hash_count; j++) {
		if (stored_hash == sign_hashes[j].value ||
		    stored_hash == SMW_ATTR_HASH_ANY) {
			append_algo_name(sign_hashes[j].name, buffer,
					 buffer_size, written, first);
		}
	}
}

/**
 * @brief Map a KDF algo enum value to its CLI name using generated table
 *
 * @param algo The SMW_ATTR_ALGO_* value for the KDF
 */
static const char *kdf_algo_to_name(unsigned long long algo)
{
	const struct asym_algo_mapping *table = NULL;
	size_t count = 0;
	size_t i = 0;

	table = get_tls_algo_mappings();
	count = get_tls_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (table[i].value == algo)
			return table[i].name;
	}

	table = get_kdf_algo_mappings();
	count = get_kdf_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (table[i].value == algo)
			return table[i].name;
	}

	return NULL;
}

/**
 * @brief Map a hash enum value to its CLI name using generated table
 *
 * @param hash The SMW_ATTR_HASH_* value
 * @return Static string name, or NULL if unknown
 */
static const char *hash_value_to_name(unsigned long long hash)
{
	const struct asym_algo_mapping *hash_table = NULL;
	size_t hash_count = 0;
	size_t i;

	if (hash == SMW_ATTR_HASH_ANY)
		return NULL;
	if (hash == SMW_ATTR_HASH_NONE)
		return NULL;

	hash_table = get_sign_hash_algo_mappings();
	hash_count = get_sign_hash_algo_mappings_count();

	for (i = 0; i < hash_count; i++) {
		if (hash_table[i].value == hash)
			return hash_table[i].name;
	}

	return NULL;
}

/**
 * @brief Check and append key derivation algorithms to output buffer
 *
 * Follows the same pattern as check_ecdsa_algo / check_rsa_algo:
 * decodes the stored permitted_algo and expands ANY hashes.
 */
static void check_kdf_algo(smw_attr_algo_t permitted_algo,
			   const struct asym_algo_mapping *sign_hashes,
			   size_t hash_count, char *buffer, size_t buffer_size,
			   size_t *written, bool *first)
{
	char algo_name[USAGE_STR_LEN];
	smw_attr_algo_t stored_class = SMW_ATTR_GET_CLASS(permitted_algo);
	smw_attr_algo_t stored_algo = SMW_ATTR_GET_ALGO(permitted_algo);
	smw_attr_algo_t stored_hash = SMW_ATTR_GET_HASH(permitted_algo);
	const char *kdf_name = NULL;
	const char *hash_name = NULL;
	size_t j;

	if (stored_class != SMW_ATTR_CLASS_KEY_DERIVATION)
		return;

	kdf_name = kdf_algo_to_name(stored_algo);
	if (!kdf_name)
		return;

	/* Specific hash: print "KDF-HASH" */
	if (stored_hash != SMW_ATTR_HASH_ANY &&
	    stored_hash != SMW_ATTR_HASH_NONE) {
		hash_name = hash_value_to_name(stored_hash);
		if (hash_name) {
			SNPRINTF(algo_name, sizeof(algo_name), "%s-%s",
				 kdf_name, hash_name);
			append_algo_name(algo_name, buffer, buffer_size,
					 written, first);
		}
		return;
	}

	/* ANY hash: expand all known hashes */
	if (stored_hash == SMW_ATTR_HASH_ANY) {
		for (j = 0; j < hash_count; j++) {
			SNPRINTF(algo_name, sizeof(algo_name), "%s-%s",
				 kdf_name, sign_hashes[j].name);
			append_algo_name(algo_name, buffer, buffer_size,
					 written, first);
		}
		return;
	}

	/* NONE hash: just the KDF name */
	append_algo_name(kdf_name, buffer, buffer_size, written, first);
}

/**
 * @brief Convert permitted algorithm to human-readable string
 */
static void permitted_algo_to_string(smw_attr_algo_t permitted_algo,
				     smw_key_type_t key_type, char *buffer,
				     size_t buffer_size)
{
	const struct asym_algo_mapping *sign_modes = NULL;
	const struct asym_algo_mapping *encrypt_modes = NULL;
	const struct asym_algo_mapping *sign_hashes = NULL;
	const struct asym_algo_mapping *eddsa_algos = NULL;
	size_t sign_mode_count = 0;
	size_t encrypt_mode_count = 0;
	size_t hash_count = 0;
	size_t eddsa_algo_count = 0;
	size_t written = 0;
	bool first = true;
	uint32_t key_type_value = (uint32_t)key_type;
	const char *key_type_str = NULL;
	smw_attr_algo_t stored_class = SMW_ATTR_GET_CLASS(permitted_algo);

	if (!buffer || !buffer_size)
		return;

	buffer[0] = '\0';

	key_type_str = asym_key_type_to_string(key_type_value);

	sign_modes = get_sign_mode_mappings();
	sign_mode_count = get_sign_mode_mappings_count();

	encrypt_modes = get_encrypt_mode_mappings();
	encrypt_mode_count = get_encrypt_mode_mappings_count();

	sign_hashes = get_sign_hash_algo_mappings();
	hash_count = get_sign_hash_algo_mappings_count();

	if (!sign_hashes || !hash_count) {
		LOG_ERROR("Failed to get sign hash algorithm mappings");
		return;
	}

	if (!encrypt_modes || !encrypt_mode_count) {
		LOG_ERROR("Failed to get encrypt mode mappings");
		return;
	}

	if (!sign_modes || !sign_mode_count) {
		LOG_ERROR("Failed to get sign mode mappings");
		return;
	}

	eddsa_algos = get_eddsa_algo_mappings();
	eddsa_algo_count = get_eddsa_algo_mappings_count();

	if (stored_class == SMW_ATTR_CLASS_KEY_DERIVATION) {
		check_kdf_algo(permitted_algo, sign_hashes, hash_count, buffer,
			       buffer_size, &written, &first);
		if (!written && buffer_size > 0)
			SNPRINTF(buffer, buffer_size, "none");
		return;
	}

	if (is_asym_rsa_sig_type(key_type_str) ||
	    is_asym_rsa_enc_type(key_type_str)) {
		check_rsa_algo(permitted_algo, sign_modes, sign_mode_count,
			       encrypt_modes, encrypt_mode_count, sign_hashes,
			       hash_count, buffer, buffer_size, &written,
			       &first);
	}

	if (is_asym_ecdsa_sig_type(key_type_str)) {
		check_ecdsa_algo(permitted_algo, sign_hashes, hash_count,
				 buffer, buffer_size, &written, &first);
	}

	if (is_asym_eddsa_sig_type(key_type_str)) {
		check_eddsa_algo(permitted_algo, eddsa_algos, eddsa_algo_count,
				 buffer, buffer_size, &written, &first);
	}

	if (is_asym_dsa_sig_type(key_type_str)) {
		check_dsa_algo(permitted_algo, sign_hashes, hash_count, buffer,
			       buffer_size, &written, &first);
	}

	if (!written && buffer_size > 0)
		SNPRINTF(buffer, buffer_size, "none");
}

/**
 * @brief Print key generation result
 */
static void print_key_result(const struct smw_key_descriptor *key_desc,
			     bool transient, bool sensitive)
{
	char usage_str[USAGE_STR_MAX_LEN] = { 0 };
	char algo_str[ALGO_STR_MAX_LEN] = { 0 };
	struct smw_get_key_attributes_args get_attr_args = { 0 };
	struct smw_key_descriptor query_key = { 0 };
	struct smw_key_attributes query_key_attrs = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int actual_size = key_desc->security_size;

	query_key.id = key_desc->id;
	query_key.type_name = key_desc->type_name;
	query_key.attributes = query_key_attrs;

	get_attr_args.version = 0;
	get_attr_args.key_descriptor = &query_key;

	status = smw_get_key_attributes(&get_attr_args);
	if (status == SMW_STATUS_OK) {
		actual_size = query_key.security_size;
		usage_flags_to_string(query_key.attributes.usage_flags,
				      usage_str, sizeof(usage_str));
		permitted_algo_to_string(query_key.attributes.permitted_algo,
					 query_key.type_name, algo_str,
					 sizeof(algo_str));
	} else {
		usage_flags_to_string(key_desc->attributes.usage_flags,
				      usage_str, sizeof(usage_str));
		permitted_algo_to_string(key_desc->attributes.permitted_algo,
					 key_desc->type_name, algo_str,
					 sizeof(algo_str));
	}

	printf("\n");
	printf("Asymmetric key pair generated successfully\n");
	printf("==========================================\n");
	printf("ID: 0x%08x (%u) | Type: %s | Size: %u bits\n", key_desc->id,
	       key_desc->id,
	       asym_key_type_to_string((uint32_t)key_desc->type_name),
	       actual_size);
	printf("Usage: %s\n", usage_str);
	printf("Permitted algo: %s\n", algo_str);
	printf("Persistence: %s | Sensitive: %s\n",
	       transient ? "transient" : "persistent",
	       sensitive ? "yes" : "no");
	printf("\n");
}

/**
 * @brief Display help information for asymmetric key generation (SMW API)
 */
void cli_keygen_asym_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Asymmetric Key Generation Operation - SMW API\n\n");

	cli_keygen_asym_help_common();

	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("\nExamples:\n");
	printf("  %s keygen-asym -t RSA -s 2048 -a PSS-SHA256 -u sign,verify -i 1\n\n",
	       prog_name);
	printf("  %s keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 -u sign,verify",
	       prog_name);
	printf(" -i 0x12345678\n\n");
}

/**
 * @brief Execute asymmetric key generation using SMW API
 */
enum cli_exit_code cli_keygen_asym_operation(struct parsed_options *args)
{
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_key_attributes key_attrs = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	uint32_t key_type_value = 0;
	smw_key_type_t key_type = SMW_KEY_TYPE_NAME_NONE;
	smw_attr_algo_t permitted_algo = 0;
	smw_attr_usage_t usage_flags = 0;
	uint32_t fixed_size = 0;
	unsigned int security_size = 0;
	struct smw_key_info key_info = { 0 };

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Asymmetric key generation operation (SMW API)");

	if (parse_asym_key_type(args->op.keygen.key_type, &fixed_size,
				&key_type_value) != 0) {
		LOG_ERROR("Invalid key type: %s", args->op.keygen.key_type);
		goto cleanup;
	}

	if (key_type_value > (uint32_t)INT32_MAX) {
		LOG_ERROR("Key type value out of range: 0x%08x",
			  key_type_value);
		goto cleanup;
	}
	key_type = (smw_key_type_t)key_type_value;

	if (fixed_size != 0) {
		security_size = fixed_size;
		if (args->op.keygen.key_size &&
		    args->op.keygen.key_size != fixed_size) {
			printf("\nWarning: Key type %s has fixed size %u bits, ignoring -s %u\n",
			       args->op.keygen.key_type, fixed_size,
			       args->op.keygen.key_size);
		}
	} else {
		if (args->op.keygen.key_size == 0) {
			LOG_ERROR("Key type %s requires --size parameter",
				  args->op.keygen.key_type);
			goto cleanup;
		}
		security_size = args->op.keygen.key_size;
	}

	/* Always parse the algorithm — key exchange types get KDF algo */
	if (parse_smw_multi_algos(args->op.keygen.permitted_algo,
				  args->op.keygen.key_type, &permitted_algo)) {
		goto cleanup;
	}

	usage_flags = parse_smw_usage_flags(args->op.keygen.usage);
	if (!usage_flags) {
		LOG_ERROR("Invalid or empty usage flags: %s",
			  args->op.keygen.usage);
		goto cleanup;
	}

	memset(&key_attrs, 0, sizeof(key_attrs));
	key_attrs.permitted_algo = permitted_algo;
	key_attrs.usage_flags = usage_flags;
	key_attrs.storage_id = 0;

	if (args->op.keygen.transient)
		key_attrs.attributes =
			SMW_ATTR_SET_TRANSIENT(key_attrs.attributes);
	else
		key_attrs.attributes =
			SMW_ATTR_SET_PERSISTENT(key_attrs.attributes);

	if (args->op.keygen.non_sensitive)
		key_attrs.attributes =
			SMW_ATTR_CLEAR_SENSITIVE(key_attrs.attributes);
	else
		key_attrs.attributes =
			SMW_ATTR_SET_SENSITIVE(key_attrs.attributes);

	key_desc.type_name = key_type;
	key_desc.security_size = security_size;
	key_desc.id = args->op.keygen.key_id;
	key_desc.buffer = NULL;
	key_desc.attributes = key_attrs;

	gen_args.version = 0;
	gen_args.key_descriptor = &key_desc;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE)
		gen_args.subsystem_name = args->subsystem;

	key_info.key_type_name = key_type;
	key_info.security_size = security_size;

	status = smw_config_check_generate_key(gen_args.subsystem_name,
					       &key_info);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_config_check_generate_key",
					status))
			goto cleanup;
	}

	log_smw_keygen_params(&gen_args);

	status = smw_generate_key(&gen_args);
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		is_smw_api_success("smw_generate_key", status);
		goto cleanup;
	}

	if (status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		printf("\nWarning: Key generated successfully,");
		printf(" but some policy elements were ignored\n");
	}

	print_key_result(&key_desc, args->op.keygen.transient,
			 !args->op.keygen.non_sensitive);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (args) {
		if (args->op.keygen.key_type) {
			free(args->op.keygen.key_type);
			args->op.keygen.key_type = NULL;
		}
		if (args->op.keygen.permitted_algo) {
			free(args->op.keygen.permitted_algo);
			args->op.keygen.permitted_algo = NULL;
		}
		if (args->op.keygen.usage) {
			free(args->op.keygen.usage);
			args->op.keygen.usage = NULL;
		}
		if (args->log_filename) {
			free(args->log_filename);
			args->log_filename = NULL;
		}
	}

	return ret;
}
