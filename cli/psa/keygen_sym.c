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
#include "cli_print.h"
#include "common.h"
#include "helper.h"
#include "key_sym_mappings.h"
#include "keygen_common.h"
#include "logger.h"
#include "parser_keygen_sym.h"
#include "utils.h"

#define USAGE_STR_MAX_LEN 256

/**
 * @brief Parse a single algorithm string based on key type
 *
 * @param algo_str Algorithm string (e.g., "GCM", "SHA256")
 * @param key_type Key type string (e.g., "AES", "HMAC")
 */
static psa_algorithm_t parse_psa_single_algorithm(const char *algo_str,
						  const char *key_type)
{
	size_t i = 0;
	const struct algo_mapping *hmac_hash_algos = NULL;
	const struct algo_mapping *aead_algos = NULL;
	const struct algo_mapping *cipher_algos = NULL;
	const struct algo_mapping *cmac_algos = NULL;
	size_t hmac_count = 0;
	size_t aead_count = 0;
	size_t cipher_count = 0;
	size_t cmac_count = 0;

	if (!algo_str)
		return PSA_ALG_NONE;

	LOG_VERBOSE("Parsing PSA single algorithm: %s (key_type=%s)", algo_str,
		    key_type ? key_type : "NULL");

	/* HMAC: search hash algorithm table */
	if (key_type && !strcasecmp(key_type, "HMAC")) {
		hmac_hash_algos = get_hmac_hash_algo_mappings();
		hmac_count = get_hmac_hash_algo_mappings_count();
		for (i = 0; i < hmac_count; i++) {
			if (hmac_hash_algos[i].name &&
			    !strcasecmp(algo_str, hmac_hash_algos[i].name)) {
				LOG_VERBOSE("  HMAC hash resolved: %s = 0x%08x",
					    algo_str, hmac_hash_algos[i].value);
				return hmac_hash_algos[i].value;
			}
		}
		LOG_VERBOSE("  HMAC hash not found: %s", algo_str);
		return PSA_ALG_NONE;
	}

	/* Try CMAC modes */
	cmac_algos = get_cmac_algo_mappings();
	cmac_count = get_cmac_algo_mappings_count();
	for (i = 0; i < cmac_count; i++) {
		if (cmac_algos[i].name &&
		    !strcasecmp(algo_str, cmac_algos[i].name)) {
			LOG_VERBOSE("  CMAC mode resolved: %s = 0x%08x",
				    algo_str, cmac_algos[i].value);
			return cmac_algos[i].value;
		}
	}

	/* Try AEAD */
	aead_algos = get_aead_algo_mappings();
	aead_count = get_aead_algo_mappings_count();
	for (i = 0; i < aead_count; i++) {
		if (aead_algos[i].name &&
		    !strcasecmp(algo_str, aead_algos[i].name)) {
			LOG_VERBOSE("  AEAD mode resolved: %s = 0x%08x",
				    algo_str, aead_algos[i].value);
			return aead_algos[i].value;
		}
	}

	/* Try cipher */
	cipher_algos = get_cipher_algo_mappings();
	cipher_count = get_cipher_algo_mappings_count();
	for (i = 0; i < cipher_count; i++) {
		if (cipher_algos[i].name &&
		    !strcasecmp(algo_str, cipher_algos[i].name)) {
			LOG_VERBOSE("  Cipher mode resolved: %s = 0x%08x",
				    algo_str, cipher_algos[i].value);
			return cipher_algos[i].value;
		}
	}

	LOG_VERBOSE("  Algorithm not found: %s", algo_str);
	return PSA_ALG_NONE;
}

/**
 * @brief Parse permitted algorithm (takes first valid one for PSA)
 *
 * @param algo_str Comma-separated algorithm list (e.g., "GCM,CTR")
 * @param key_type Key type string (e.g., "AES", "HMAC")
 */
static psa_algorithm_t parse_psa_permitted_algo(const char *algo_str,
						const char *key_type)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	psa_algorithm_t algorithm = PSA_ALG_NONE;

	if (!algo_str || !key_type)
		return PSA_ALG_NONE;

	LOG_VERBOSE("Parsing PSA permitted algo: %s (key_type=%s)", algo_str,
		    key_type);

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return PSA_ALG_NONE;

	/* PSA supports only one algorithm per key, take the first */
	token = strtok_r(algo_copy, ",", &saveptr);
	if (token) {
		algorithm = parse_psa_single_algorithm(token, key_type);
		LOG_VERBOSE("PSA permitted algo (first token '%s'): 0x%08x",
			    token, (unsigned int)algorithm);
	}

	free(algo_copy);
	return algorithm;
}

/**
 * @brief Convert PSA algorithm value to string
 *
 * @param alg PSA algorithm value
 */
static const char *psa_algorithm_to_string(psa_algorithm_t alg)
{
	size_t i = 0;
	const struct algo_mapping *hmac_hash_algos = NULL;
	const struct algo_mapping *aead_algos = NULL;
	const struct algo_mapping *cipher_algos = NULL;
	const struct algo_mapping *cmac_algos = NULL;
	size_t hmac_count = 0;
	size_t aead_count = 0;
	size_t cipher_count = 0;
	size_t cmac_count = 0;

	if (alg == PSA_ALG_NONE)
		return "NONE";

	/* Check HMAC hash algorithms */
	hmac_hash_algos = get_hmac_hash_algo_mappings();
	hmac_count = get_hmac_hash_algo_mappings_count();
	for (i = 0; i < hmac_count; i++) {
		if (hmac_hash_algos[i].value == alg)
			return hmac_hash_algos[i].name;
	}

	/* Check CMAC modes */
	cmac_algos = get_cmac_algo_mappings();
	cmac_count = get_cmac_algo_mappings_count();
	for (i = 0; i < cmac_count; i++) {
		if (cmac_algos[i].value == alg)
			return cmac_algos[i].name;
	}

	/* Check AEAD */
	aead_algos = get_aead_algo_mappings();
	aead_count = get_aead_algo_mappings_count();
	for (i = 0; i < aead_count; i++) {
		if (aead_algos[i].value == alg)
			return aead_algos[i].name;
	}

	/* Check cipher */
	cipher_algos = get_cipher_algo_mappings();
	cipher_count = get_cipher_algo_mappings_count();
	for (i = 0; i < cipher_count; i++) {
		if (cipher_algos[i].value == alg)
			return cipher_algos[i].name;
	}

	return "UNKNOWN";
}

/**
 * @brief Print key generation result
 *
 * @param key_id     Generated key identifier
 * @param attributes Pointer to key attributes
 * @param transient  Whether key is transient (volatile)
 */
static void print_key_result(psa_key_id_t key_id,
			     const psa_key_attributes_t *attributes,
			     bool transient)
{
	char usage_str[USAGE_STR_MAX_LEN] = { 0 };
	psa_algorithm_t actual_algo;
	const char *algo_name;

	usage_flags_to_string(psa_get_key_usage_flags(attributes), usage_str,
			      sizeof(usage_str));

	actual_algo = psa_get_key_algorithm(attributes);
	algo_name = psa_algorithm_to_string(actual_algo);

	SUCCESS("Symmetric key generation");
	INFO("Key ID", "0x%08x (%u)", key_id, key_id);
	INFO("Type", "%s", key_type_to_string(psa_get_key_type(attributes)));
	INFO("Size", "%zu bits", psa_get_key_bits(attributes));
	INFO("Usage", "%s", usage_str);
	INFO("Algorithm", "%s", algo_name);
	INFO("Persistent", "%s", transient ? "no" : "yes");
	printf("\n");
}

/**
 * @brief Display help information for symmetric key generation (PSA API)
 */
void cli_keygen_sym_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Symmetric Key Generation Operation - PSA API\n\n");

	cli_keygen_sym_help_common();

	printf("\nNote:");
	printf(" PSA supports only ONE algorithm per key (first one is used)\n");

	printf("\nExamples:\n");
	printf("  %s keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt -i 1\n",
	       prog_name);
	printf("  %s keygen-sym -t HMAC -s 256 -a SHA256 -u sign,verify",
	       prog_name);
	printf(" -i 0x12345678\n\n");
}

/**
 * @brief Execute symmetric key generation using PSA API
 *
 * Generates a symmetric cryptographic key using psa_generate_key() and
 * displays the key properties.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_keygen_sym_operation(struct parsed_options *args)
{
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	psa_key_type_t key_type = PSA_KEY_TYPE_NONE;
	psa_algorithm_t algorithm = PSA_ALG_NONE;
	psa_key_usage_t usage_flags = 0;
	psa_key_id_t key_id = 0;
	uint32_t kt_value = 0;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Symmetric key generation operation started (PSA API)");
	LOG_VERBOSE("  key_type       : %s", args->op.keygen.key_type);
	LOG_VERBOSE("  key_size       : %u bits", args->op.keygen.key_size);
	LOG_VERBOSE("  key_id         : 0x%08x (%u)", args->op.keygen.key_id,
		    args->op.keygen.key_id);
	LOG_VERBOSE("  permitted_algo : %s", args->op.keygen.permitted_algo);
	LOG_VERBOSE("  usage          : %s", args->op.keygen.usage);
	LOG_VERBOSE("  transient      : %s",
		    args->op.keygen.transient ? "yes" : "no");

	/* Parse key type */
	LOG_VERBOSE("Parsing key type: %s", args->op.keygen.key_type);
	if (parse_key_type(args->op.keygen.key_type, &kt_value)) {
		LOG_ERROR("Invalid key type: %s", args->op.keygen.key_type);
		goto cleanup;
	}

	if (kt_value > (uint32_t)UINT16_MAX) {
		LOG_ERROR("Key type value 0x%08x out of range for PSA key type",
			  kt_value);
		goto cleanup;
	}

	key_type = (psa_key_type_t)kt_value;
	LOG_VERBOSE("Key type resolved: %s (0x%04x)",
		    key_type_to_string(key_type), kt_value);

	/* Parse permitted algorithm (PSA takes only first one) */
	LOG_VERBOSE("Parsing permitted algorithm: %s",
		    args->op.keygen.permitted_algo);
	algorithm = parse_psa_permitted_algo(args->op.keygen.permitted_algo,
					     args->op.keygen.key_type);
	if (algorithm == PSA_ALG_NONE) {
		LOG_ERROR("Invalid permitted algorithm: %s",
			  args->op.keygen.permitted_algo);
		goto cleanup;
	}

	LOG_VERBOSE("Algorithm resolved: %s (0x%08x)",
		    psa_algorithm_to_string(algorithm),
		    (unsigned int)algorithm);

	/* Parse usage flags */
	LOG_VERBOSE("Parsing usage flags: %s", args->op.keygen.usage);
	usage_flags = parse_psa_usage_flags(args->op.keygen.usage);
	if (!usage_flags) {
		LOG_ERROR("Invalid or empty usage flags: %s",
			  args->op.keygen.usage);
		goto cleanup;
	}

	LOG_VERBOSE("Usage flags resolved: 0x%08x", (unsigned int)usage_flags);

	/* Setup key attributes */
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, args->op.keygen.key_size);
	psa_set_key_algorithm(&attributes, algorithm);
	psa_set_key_usage_flags(&attributes, usage_flags);

	/* Set lifetime (transient or persistent) */
	if (args->op.keygen.transient) {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
		LOG_VERBOSE("Key lifetime: VOLATILE (transient)");
	} else {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
		psa_set_key_id(&attributes, args->op.keygen.key_id);
		LOG_VERBOSE("Key lifetime: PERSISTENT (id=0x%08x)",
			    args->op.keygen.key_id);
	}

	/* Log PSA API parameters */
	log_psa_keygen_params(&attributes, args->op.keygen.key_id);

	/* Call PSA key generation API */
	LOG_VERBOSE("Calling psa_generate_key()");
	status = psa_generate_key(&attributes, &key_id);
	if (!is_psa_api_success("psa_generate_key", status))
		goto cleanup;

	/* Retrieve actual attributes from subsystem */
	LOG_VERBOSE("Retrieving key attributes via psa_get_key_attributes()");
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
			LOG_VERBOSE("Freeing key type buffer");
			free(args->op.keygen.key_type);
			args->op.keygen.key_type = NULL;
		}
		if (args->op.keygen.permitted_algo) {
			LOG_VERBOSE("Freeing permitted algo buffer");
			free(args->op.keygen.permitted_algo);
			args->op.keygen.permitted_algo = NULL;
		}
		if (args->op.keygen.usage) {
			LOG_VERBOSE("Freeing usage buffer");
			free(args->op.keygen.usage);
			args->op.keygen.usage = NULL;
		}
		if (args->log_filename) {
			LOG_VERBOSE("Freeing log filename buffer");
			free(args->log_filename);
			args->log_filename = NULL;
		}
	}

	return ret;
}
