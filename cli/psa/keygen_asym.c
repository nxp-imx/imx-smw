// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <psa/crypto.h>
#include "apis_dispatcher.h"
#include "builtin_macros.h"
#include "cli_print.h"
#include "common.h"
#include "helper.h"
#include "keygen_common.h"
#include "key_asym_mappings.h"
#include "logger.h"
#include "parser_keygen_asym.h"
#include "psa_asym_key_mappings_generated.h"
#include "utils.h"

#define USAGE_STR_LEN	  64
#define USAGE_STR_MAX_LEN 256
#define ALGO_STR_MAX_LEN  512

/**
 * @brief Convert asymmetric algorithm to human-readable string
 *
 * @param alg PSA algorithm value
 */
static const char *psa_algorithm_to_string(psa_algorithm_t alg)
{
	static char algo_buf[128];
	psa_algorithm_t hash_alg;
	const struct asym_algo_mapping *hash_algos = NULL;
	const struct asym_algo_mapping *eddsa_algos = NULL;
	const struct asym_algo_mapping *encrypt_modes = NULL;
	size_t hash_count = 0;
	size_t eddsa_count = 0;
	size_t encrypt_mode_count = 0;
	size_t i = 0;

	if (alg == PSA_ALG_NONE)
		return "NONE";

	hash_algos = get_sign_hash_algo_mappings();
	hash_count = get_sign_hash_algo_mappings_count();

	/* RSA PSS */
	if (PSA_ALG_IS_RSA_PSS(alg)) {
		hash_alg = PSA_ALG_GET_HASH(alg);
		for (i = 0; i < hash_count; i++) {
			if (hash_algos[i].value > (uint64_t)UINT32_MAX)
				continue;
			if ((uint32_t)hash_algos[i].value == hash_alg) {
				SNPRINTF(algo_buf, sizeof(algo_buf), "PSS-%s",
					 hash_algos[i].name);
				return algo_buf;
			}
		}
		return "PSS-UNKNOWN";
	}

	/* RSA PKCS1V15 Sign */
	if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg)) {
		hash_alg = PSA_ALG_GET_HASH(alg);
		for (i = 0; i < hash_count; i++) {
			if (hash_algos[i].value > (uint64_t)UINT32_MAX)
				continue;
			if ((uint32_t)hash_algos[i].value == hash_alg) {
				SNPRINTF(algo_buf, sizeof(algo_buf),
					 "PKCS1V15-%s", hash_algos[i].name);
				return algo_buf;
			}
		}
		return "PKCS1V15-UNKNOWN";
	}

	/* RSA encryption */
	if (PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg)) {
		encrypt_modes = get_encrypt_mode_mappings();
		encrypt_mode_count = get_encrypt_mode_mappings_count();

		/* OAEP: has a hash component */
		if (PSA_ALG_IS_RSA_OAEP(alg)) {
			hash_alg = PSA_ALG_GET_HASH(alg);
			for (i = 0; i < hash_count; i++) {
				if (hash_algos[i].value > (uint64_t)UINT32_MAX)
					continue;
				if ((uint32_t)hash_algos[i].value == hash_alg) {
					SNPRINTF(algo_buf, sizeof(algo_buf),
						 "OAEP-%s", hash_algos[i].name);
					return algo_buf;
				}
			}
			return "OAEP-UNKNOWN";
		}

		for (i = 0; i < encrypt_mode_count; i++) {
			if (!encrypt_modes[i].name)
				continue;
			if (!strcasecmp(encrypt_modes[i].name, "PKCS1V15") &&
			    alg == PSA_ALG_RSA_PKCS1V15_CRYPT) {
				SNPRINTF(algo_buf, sizeof(algo_buf), "%s-CRYPT",
					 encrypt_modes[i].name);
				return algo_buf;
			}
		}
		return "ENCRYPT-UNKNOWN";
	}

	/* ECDSA */
	if (PSA_ALG_IS_ECDSA(alg)) {
		hash_alg = PSA_ALG_GET_HASH(alg);
		for (i = 0; i < hash_count; i++) {
			if (!hash_algos[i].name)
				continue;
			if (hash_algos[i].value > (uint64_t)UINT32_MAX)
				continue;
			if ((uint32_t)hash_algos[i].value == hash_alg) {
				SNPRINTF(algo_buf, sizeof(algo_buf), "ECDSA-%s",
					 hash_algos[i].name);
				return algo_buf;
			}
		}
		return "ECDSA-UNKNOWN";
	}

	/* EdDSA */
	if (PSA_ALG_IS_SIGN(alg)) {
		eddsa_algos = get_eddsa_algo_mappings();
		eddsa_count = get_eddsa_algo_mappings_count();
		for (i = 0; i < eddsa_count; i++) {
			if (eddsa_algos[i].value > (uint64_t)UINT32_MAX)
				continue;
			if (eddsa_algos[i].name &&
			    (uint32_t)eddsa_algos[i].value == alg) {
				/*
				 * Strip the curve suffix for display:
				 * "EDDSA-PREHASHED-ED448" -> "EDDSA-PREHASHED"
				 */
				if (strncasecmp(eddsa_algos[i].name,
						"EDDSA-PREHASHED-",
						strlen("EDDSA-PREHASHED-")) ==
				    0)
					return "EDDSA-PREHASHED";
				return eddsa_algos[i].name;
			}
		}
	}

	/* TLS and KDF algorithms */
	if (PSA_ALG_IS_TLS12_PRF(alg) || PSA_ALG_IS_VENDOR_TLS13(alg) ||
	    PSA_ALG_IS_ECDH(alg) || PSA_ALG_IS_FFDH(alg)) {
		const struct asym_algo_mapping *tbls[2] = {
			get_tls_algo_mappings(),
			get_kdf_algo_mappings(),
		};
		size_t counts[2] = {
			get_tls_algo_mappings_count(),
			get_kdf_algo_mappings_count(),
		};
		const struct asym_algo_mapping *entry = NULL;
		psa_algorithm_t alg_base = alg & ~PSA_ALG_HASH_MASK;
		size_t t = 0;
		size_t j = 0;

		hash_alg = PSA_ALG_GET_HASH(alg);

		for (t = 0; t < 2; t++) {
			for (i = 0; i < counts[t]; i++) {
				entry = &tbls[t][i];
				if (!entry->name)
					continue;

				/* Bare match — no hash (ECDH, DH) */
				if (entry->value <= (uint64_t)UINT32_MAX &&
				    (uint32_t)entry->value == alg)
					return entry->name;

				/* Hash-based match */
				if ((uint64_t)alg_base != entry->value)
					continue;

				for (j = 0; j < hash_count; j++) {
					if (hash_algos[j].value >
					    (uint64_t)UINT32_MAX)
						continue;
					if ((uint32_t)hash_algos[j].value !=
					    hash_alg)
						continue;
					SNPRINTF(algo_buf, sizeof(algo_buf),
						 "%s-%s", entry->name,
						 hash_algos[j].name);
					return algo_buf;
				}
			}
		}
		return "KDF-UNKNOWN";
	}

	SNPRINTF(algo_buf, sizeof(algo_buf), "UNKNOWN-0x%08x",
		 (unsigned int)alg);
	return algo_buf;
}

/**
 * @brief Parse hash algorithm from string using generated tables
 *
 * @param hash_str Hash algorithm name (e.g., "SHA256", "SHA512")
 */
static psa_algorithm_t parse_hash_algo(const char *hash_str)
{
	size_t i = 0;
	const struct asym_algo_mapping *hash_algos = NULL;
	size_t hash_count = 0;

	if (!hash_str)
		return PSA_ALG_NONE;

	hash_algos = get_sign_hash_algo_mappings();
	hash_count = get_sign_hash_algo_mappings_count();

	for (i = 0; i < hash_count; i++) {
		if (hash_algos[i].name &&
		    !strcasecmp(hash_str, hash_algos[i].name))
			return (psa_algorithm_t)hash_algos[i].value;
	}

	LOG_ERROR("Unknown hash algorithm: %s", hash_str);
	return PSA_ALG_NONE;
}

/**
 * @brief Generic parser for "MODE-HASH" format algorithms
 *
 * @param algo_str Algorithm string (e.g., "PSS-SHA256")
 * @param mode_out Output for mode part (e.g., "PSS")
 * @param hash_out Output for hash part (e.g., "SHA256")
 */
static int split_mode_hash(const char *algo_str, char **mode_out,
			   char **hash_out)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;

	if (!algo_str || !mode_out || !hash_out)
		return -1;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return -1;

	token = strtok_r(algo_copy, "-", &saveptr);
	if (!token || !saveptr) {
		free(algo_copy);
		return -1;
	}

	*mode_out = strdup(token);
	*hash_out = strdup(saveptr);

	free(algo_copy);

	if (!*mode_out || !*hash_out) {
		free(*mode_out);
		free(*hash_out);
		return -1;
	}

	return 0;
}

/**
 * @brief Parse KDF/TLS algorithm from string
 *
 * Checks both TLS table (TLS12, TLS13) and KDF table (ECDH, DH).
 *
 * @param algo_str Algorithm string (e.g. "TLS13-SHA256", "ECDH")
 */
static psa_algorithm_t parse_kdf_algo(const char *algo_str)
{
	char *algo_copy = NULL;
	char *kdf_str = NULL;
	char *hash_str = NULL;
	char *saveptr = NULL;
	psa_algorithm_t hash_algo = PSA_ALG_NONE;
	psa_algorithm_t result = PSA_ALG_NONE;
	const struct asym_algo_mapping *tbl = NULL;
	size_t count = 0;
	size_t i = 0;
	uint64_t combined = 0;

	if (!algo_str)
		return PSA_ALG_NONE;

	tbl = get_tls_algo_mappings();
	count = get_tls_algo_mappings_count();
	for (; i < count; i++) {
		if (tbl[i].name && !strcasecmp(algo_str, tbl[i].name))
			return (psa_algorithm_t)tbl[i].value;
	}

	tbl = get_kdf_algo_mappings();
	count = get_kdf_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (tbl[i].name && !strcasecmp(algo_str, tbl[i].name))
			return (psa_algorithm_t)tbl[i].value;
	}

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return PSA_ALG_NONE;

	kdf_str = strtok_r(algo_copy, "-", &saveptr);
	hash_str = saveptr;

	if (!kdf_str || !hash_str)
		goto cleanup;

	/* Check TLS table */
	tbl = get_tls_algo_mappings();
	count = get_tls_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (!tbl[i].name)
			continue;
		if (!strcasecmp(kdf_str, tbl[i].name)) {
			hash_algo = parse_hash_algo(hash_str);
			if (hash_algo == PSA_ALG_NONE)
				goto cleanup;

			combined =
				tbl[i].value | (hash_algo & PSA_ALG_HASH_MASK);
			if (SET_OVERFLOW(combined, result))
				LOG_ERROR("KDF algorithm value overflow");
			goto cleanup;
		}
	}

	/* Check KDF table */
	tbl = get_kdf_algo_mappings();
	count = get_kdf_algo_mappings_count();
	for (i = 0; i < count; i++) {
		if (!tbl[i].name)
			continue;
		if (!strcasecmp(kdf_str, tbl[i].name)) {
			hash_algo = parse_hash_algo(hash_str);
			if (hash_algo == PSA_ALG_NONE)
				goto cleanup;

			combined =
				tbl[i].value | (hash_algo & PSA_ALG_HASH_MASK);
			if (SET_OVERFLOW(combined, result))
				LOG_ERROR("KDF algorithm value overflow");
			goto cleanup;
		}
	}

cleanup:
	free(algo_copy);
	return result;
}

/**
 * @brief Parse RSA signature algorithm (e.g., "PSS-SHA256", "PKCS1V15-SHA256")
 *
 * @param algo_str Algorithm string in format "MODE-HASH"
 */
static psa_algorithm_t parse_rsa_sign_algo(const char *algo_str)
{
	char *mode_str = NULL;
	char *hash_str = NULL;
	psa_algorithm_t hash_algo = PSA_ALG_NONE;
	psa_algorithm_t result = PSA_ALG_NONE;

	if (!algo_str)
		return PSA_ALG_NONE;

	if (split_mode_hash(algo_str, &mode_str, &hash_str) != 0) {
		LOG_ERROR("Invalid RSA signature format: %s", algo_str);
		return PSA_ALG_NONE;
	}

	hash_algo = parse_hash_algo(hash_str);
	if (hash_algo == PSA_ALG_NONE)
		goto cleanup;

	if (!strcasecmp(mode_str, "PSS"))
		result = PSA_ALG_RSA_PSS(hash_algo);
	else if (!strcasecmp(mode_str, "PKCS1V15"))
		result = PSA_ALG_RSA_PKCS1V15_SIGN(hash_algo);
	else
		LOG_ERROR("Unknown RSA signature mode: %s", mode_str);

cleanup:
	free(mode_str);
	free(hash_str);
	return result;
}

/**
 * @brief Parse RSA encryption algorithm (e.g., "OAEP-SHA256", "PKCS1V15-CRYPT")
 *
 * @param algo_str Algorithm string in format "MODE-HASH" or "MODE-CRYPT"
 */
static psa_algorithm_t parse_rsa_encrypt_algo(const char *algo_str)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	char *mode_str = NULL;
	char *hash_str = NULL;
	psa_algorithm_t hash_algo = PSA_ALG_NONE;
	psa_algorithm_t result = PSA_ALG_NONE;
	const struct asym_algo_mapping *encrypt_modes = NULL;
	size_t encrypt_mode_count = 0;
	size_t i = 0;
	bool mode_found = false;

	if (!algo_str)
		return PSA_ALG_NONE;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return PSA_ALG_NONE;

	/* Expected format: MODE-HASH or MODE-CRYPT */
	token = strtok_r(algo_copy, "-", &saveptr);
	if (token) {
		mode_str = token;
		hash_str = saveptr;
	}

	if (!mode_str) {
		LOG_ERROR("Invalid RSA encryption format: %s", algo_str);
		goto cleanup;
	}

	/* Check mode against generated table */
	encrypt_modes = get_encrypt_mode_mappings();
	encrypt_mode_count = get_encrypt_mode_mappings_count();

	for (i = 0; i < encrypt_mode_count; i++) {
		if (encrypt_modes[i].name &&
		    !strcasecmp(mode_str, encrypt_modes[i].name)) {
			mode_found = true;

			if (!strcasecmp(mode_str, "OAEP")) {
				if (!hash_str) {
					LOG_ERROR("Hash algorithm required");
					goto cleanup;
				}
				hash_algo = parse_hash_algo(hash_str);
				if (hash_algo == PSA_ALG_NONE)
					goto cleanup;
				result = PSA_ALG_RSA_OAEP(hash_algo);
			} else if (!strcasecmp(mode_str, "PKCS1V15")) {
				if (hash_str &&
				    !strcasecmp(hash_str, "CRYPT")) {
					result = PSA_ALG_RSA_PKCS1V15_CRYPT;
				} else {
					LOG_ERROR("-CRYPT suffix required");
					goto cleanup;
				}
			}
			break;
		}
	}

	if (!mode_found)
		LOG_ERROR("Unknown RSA encryption mode: %s", mode_str);

cleanup:
	free(algo_copy);
	return result;
}

/**
 * @brief Parse ECDSA algorithm (e.g., "ECDSA-SHA256")
 *
 * @param algo_str Algorithm string in format "ECDSA-HASH"
 */
static psa_algorithm_t parse_ecdsa_algo(const char *algo_str)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	char *hash_str = NULL;
	psa_algorithm_t hash_algo = PSA_ALG_NONE;
	psa_algorithm_t result = PSA_ALG_NONE;

	if (!algo_str)
		return PSA_ALG_NONE;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return PSA_ALG_NONE;

	/* Expected format: ECDSA-HASH */
	token = strtok_r(algo_copy, "-", &saveptr);
	if (token && !strcasecmp(token, "ECDSA"))
		hash_str = saveptr;

	if (!hash_str) {
		LOG_ERROR("ECDSA requires a hash algorithm");
		goto cleanup;
	}

	hash_algo = parse_hash_algo(hash_str);
	if (hash_algo == PSA_ALG_NONE)
		goto cleanup;

	result = PSA_ALG_ECDSA(hash_algo);

cleanup:
	free(algo_copy);
	return result;
}

/**
 * @brief Parse EdDSA algorithm using generated tables
 *
 * The user always specifies 'EDDSA-PREHASHED' on the CLI.
 * The correct PSA algorithm is resolved from the key type:
 *   -t ED25519 -a EDDSA-PREHASHED  ->  PSA_ALG_ED25519PH
 *   -t ED448   -a EDDSA-PREHASHED  ->  PSA_ALG_ED448PH
 *   -t ED25519 -a EDDSA-PURE       ->  PSA_ALG_PURE_EDDSA
 *   -t ED448   -a EDDSA-PURE       ->  PSA_ALG_PURE_EDDSA
 *
 * @param algo_str     Algorithm string from CLI (e.g. "EDDSA-PREHASHED")
 * @param key_type_str Key type string from -t   (e.g. "ED448")
 */
static psa_algorithm_t parse_eddsa_algo(const char *algo_str,
					const char *key_type_str)
{
	const struct asym_algo_mapping *eddsa_algos = NULL;
	size_t eddsa_algo_count = 0;
	size_t i = 0;
	char lookup[USAGE_STR_LEN] = { 0 };
	bool is_prehashed = false;

	if (!algo_str)
		return PSA_ALG_NONE;

	eddsa_algos = get_eddsa_algo_mappings();
	eddsa_algo_count = get_eddsa_algo_mappings_count();

	is_prehashed = (strcasecmp(algo_str, "EDDSA-PREHASHED") == 0);

	if (is_prehashed) {
		/*
		 * Resolve to the curve-specific internal name so we can look
		 * it up in the table:
		 *   "EDDSA-PREHASHED" + key_type "ED448" -> "EDDSA-PREHASHED-ED448"
		 */
		SNPRINTF(lookup, sizeof(lookup), "EDDSA-PREHASHED-%s",
			 key_type_str);
	} else {
		/* EDDSA-PURE or any other variant: look up as-is */
		SNPRINTF(lookup, sizeof(lookup), "%s", algo_str);
	}

	for (i = 0; i < eddsa_algo_count; i++) {
		if (eddsa_algos[i].name &&
		    !strcasecmp(lookup, eddsa_algos[i].name))
			return (psa_algorithm_t)eddsa_algos[i].value;
	}

	if (is_prehashed)
		LOG_ERROR("EDDSA-PREHASHED is not supported for key type '%s'",
			  key_type_str);
	else
		LOG_ERROR("Unknown EdDSA variant: %s", algo_str);

	return PSA_ALG_NONE;
}

/**
 * @brief Parse a single algorithm string based on key type and usage
 *
 * @param algo_str Algorithm string to parse
 * @param key_type_str Key type string (e.g., "RSA", "SECP_R1")
 * @param usage_flags Key usage flags to determine context (sign/encrypt)
 */
static psa_algorithm_t parse_psa_single_algorithm(const char *algo_str,
						  const char *key_type_str,
						  psa_key_usage_t usage_flags)
{
	bool is_encryption = false;
	psa_algorithm_t kdf_result = PSA_ALG_NONE;

	if (!algo_str || !key_type_str)
		return PSA_ALG_NONE;

	is_encryption = (usage_flags &
			 (PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT)) != 0;

	kdf_result = parse_kdf_algo(algo_str);
	if (kdf_result != PSA_ALG_NONE) {
		if (!is_asym_key_ex_type(key_type_str)) {
			LOG_ERROR("Key type '%s' does not support KDF/TLS",
				  key_type_str);
			return PSA_ALG_NONE;
		}
		return kdf_result;
	}

	if (is_asym_rsa_sig_type(key_type_str)) {
		if (is_encryption)
			return parse_rsa_encrypt_algo(algo_str);
		else
			return parse_rsa_sign_algo(algo_str);
	} else if (is_asym_ecdsa_sig_type(key_type_str)) {
		return parse_ecdsa_algo(algo_str);
	} else if (is_asym_eddsa_sig_type(key_type_str)) {
		return parse_eddsa_algo(algo_str, key_type_str);
	}

	LOG_ERROR("Unknown key type or algorithm: %s for %s", algo_str,
		  key_type_str);
	return PSA_ALG_NONE;
}

/**
 * @brief Parse permitted algorithm (takes first valid one for PSA)
 *
 * @param algo_str Comma-separated algorithm list or single algorithm
 * @param key_type_str Key type string to determine algorithm context
 * @param usage_flags Key usage flags to determine context
 */
static psa_algorithm_t parse_psa_permitted_algo(const char *algo_str,
						const char *key_type_str,
						psa_key_usage_t usage_flags)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	psa_algorithm_t algorithm = PSA_ALG_NONE;

	if (!algo_str || !key_type_str)
		return PSA_ALG_NONE;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return PSA_ALG_NONE;

	/* PSA supports only one algorithm per key, take the first */
	token = strtok_r(algo_copy, ",", &saveptr);
	if (token) {
		/* Trim whitespace */
		while (*token == ' ')
			token++;

		algorithm = parse_psa_single_algorithm(token, key_type_str,
						       usage_flags);

		/* Warn if multiple algorithms specified */
		if (saveptr && *saveptr) {
			WARNING("PSA supports only one algorithm per key. Using: %s\n",
				token);
		}
	}

	free(algo_copy);
	return algorithm;
}

/**
 * @brief Get key type string for display
 *
 * @param key_type PSA key type value
 * @param key_bits Key size in bits
 */
static const char *get_key_type_string(psa_key_type_t key_type, size_t key_bits)
{
	const char *name = NULL;

	if (PSA_KEY_TYPE_IS_RSA(key_type))
		return "RSA";

	if (PSA_KEY_TYPE_IS_ECC(key_type)) {
		name = psa_key_type_to_export_name(key_type, key_bits);
		if (name)
			return name;
	}

	return "UNKNOWN";
}

/**
 * @brief Print key generation result
 *
 * @param key_id Generated key identifier
 * @param attributes Pointer to PSA key attributes
 * @param transient Whether key is transient (volatile) or persistent
 */
static void print_key_result(psa_key_id_t key_id,
			     const psa_key_attributes_t *attributes,
			     bool transient)
{
	char usage_str[USAGE_STR_MAX_LEN] = { 0 };
	psa_key_type_t key_type = psa_get_key_type(attributes);
	size_t key_bits = psa_get_key_bits(attributes);
	psa_algorithm_t actual_algo = psa_get_key_algorithm(attributes);

	usage_flags_to_string(psa_get_key_usage_flags(attributes), usage_str,
			      sizeof(usage_str));

	SUCCESS("Asymmetric key generation");
	INFO("Key ID", "0x%08x (%u)", key_id, key_id);
	INFO("Type", "%s", get_key_type_string(key_type, key_bits));
	INFO("Size", "%zu bits", key_bits);
	INFO("Usage", "%s", usage_str);
	INFO("Algorithm", "%s", psa_algorithm_to_string(actual_algo));
	INFO("Persistent", "%s", transient ? "no" : "yes");
	printf("\n");
}

/**
 * @brief Display help information for asymmetric key generation (PSA API)
 */
void cli_keygen_asym_help(void)
{
	printf("\n");
	print_tool_banner();
	printf("Asymmetric Key Generation Operation - PSA API\n\n");

	/* Print common options */
	cli_keygen_asym_help_common();

	printf("\nNote:");
	printf(" PSA supports only ONE algorithm per key (first one is used)\n");

	printf("\nExamples:\n");
	printf("  %s keygen-asym -t RSA -s 2048 -a PSS-SHA256 -u sign,verify -i 1\n",
	       get_program_name());
	printf("  %s keygen-asym -t SECP_R1 -s 256 -a ECDSA-SHA256 -u sign,verify",
	       get_program_name());
	printf(" -i 0x12345678\n\n");
}

/**
 * @brief Execute asymmetric key generation using PSA API
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_keygen_asym_operation(struct parsed_options *args)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
	psa_algorithm_t algorithm = PSA_ALG_NONE;
	psa_key_usage_t usage_flags = 0;
	psa_key_id_t key_id = 0;
	size_t key_bits = 0;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Asymmetric key generation operation (PSA API)");

	/* Parse usage flags - true for asymmetric */
	usage_flags = parse_psa_usage_flags(args->op.keygen.usage);
	if (!usage_flags) {
		LOG_ERROR("Invalid or empty usage flags: %s",
			  args->op.keygen.usage);
		goto cleanup;
	}

	/* Parse key type */
	key_type = parse_psa_asym_key_type(args->op.keygen.key_type, &key_bits);
	if (key_type == PSA_KEY_TYPE_NONE) {
		LOG_ERROR("Invalid key type: %s", args->op.keygen.key_type);
		goto cleanup;
	}

	/* Handle key size parameter */
	if (args->op.keygen.key_size != 0) {
		if (key_bits != 0 && args->op.keygen.key_size != key_bits) {
			/* User specified -s for a fixed-size key */
			WARNING("Key type %s has fixed size %zu bits, ignoring -s %u\n",
				args->op.keygen.key_type, key_bits,
				args->op.keygen.key_size);
		} else if (key_bits == 0) {
			/* Variable-size key, use user-provided size */
			key_bits = args->op.keygen.key_size;
		}
	} else if (key_bits == 0) {
		/* Variable-size key without -s parameter */
		LOG_ERROR("Key type %s requires --size parameter",
			  args->op.keygen.key_type);
		goto cleanup;
	}

	/* Parse permitted algorithm */
	algorithm =
		parse_psa_permitted_algo(args->op.keygen.permitted_algo,
					 args->op.keygen.key_type, usage_flags);
	if (algorithm == PSA_ALG_NONE) {
		goto cleanup;
	}

	/* Setup key attributes */
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, key_bits);
	psa_set_key_algorithm(&attributes, algorithm);
	psa_set_key_usage_flags(&attributes, usage_flags);

	/* Set lifetime and ID */
	if (args->op.keygen.transient) {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	} else {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
		psa_set_key_id(&attributes, args->op.keygen.key_id);
	}

	/* Log parameters */
	log_psa_keygen_params(&attributes, args->op.keygen.key_id);

	/* Call PSA key generation API */
	status = psa_generate_key(&attributes, &key_id);
	if (!is_psa_api_success("psa_generate_key", status))
		goto cleanup;

	/* Retrieve actual attributes from subsystem */
	psa_reset_key_attributes(&attributes);
	status = psa_get_key_attributes(key_id, &attributes);
	if (!is_psa_api_success("psa_get_key_attributes", status))
		goto cleanup;

	/* Print result using actual subsystem attributes */
	print_key_result(key_id, &attributes, args->op.keygen.transient);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	psa_reset_key_attributes(&attributes);

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
