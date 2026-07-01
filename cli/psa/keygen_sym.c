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
#include "common.h"
#include "helper.h"
#include "key_sym_mappings.h"
#include "logger.h"
#include "parser_keygen_sym.h"
#include "utils.h"

#define USAGE_STR_MAX_LEN 256

/**
 * @brief Parse usage flags from comma-separated string
 *
 * @param usage_str Comma-separated usage flags (e.g., "encrypt,decrypt")
 */
static psa_key_usage_t parse_psa_usage_flags(const char *usage_str)
{
	psa_key_usage_t flags = 0;
	char *usage_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;

	if (!usage_str)
		return 0;

	usage_copy = strdup(usage_str);
	if (!usage_copy)
		return 0;

	token = strtok_r(usage_copy, ",", &saveptr);
	while (token) {
		if (!strcasecmp(token, "encrypt"))
			flags |= PSA_KEY_USAGE_ENCRYPT;
		else if (!strcasecmp(token, "decrypt"))
			flags |= PSA_KEY_USAGE_DECRYPT;
		else if (!strcasecmp(token, "sign"))
			flags |= PSA_KEY_USAGE_SIGN_MESSAGE;
		else if (!strcasecmp(token, "verify"))
			flags |= PSA_KEY_USAGE_VERIFY_MESSAGE;
		else if (!strcasecmp(token, "sign_hash"))
			flags |= PSA_KEY_USAGE_SIGN_HASH;
		else if (!strcasecmp(token, "verify_hash"))
			flags |= PSA_KEY_USAGE_VERIFY_HASH;
		else
			LOG_ERROR("Unknown usage flag: %s", token);

		token = strtok_r(NULL, ",", &saveptr);
	}

	free(usage_copy);
	return flags;
}

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

	/* HMAC: search hash algorithm table */
	if (key_type && !strcasecmp(key_type, "HMAC")) {
		hmac_hash_algos = get_hmac_hash_algo_mappings();
		hmac_count = get_hmac_hash_algo_mappings_count();
		for (i = 0; i < hmac_count; i++) {
			if (hmac_hash_algos[i].name &&
			    !strcasecmp(algo_str, hmac_hash_algos[i].name))
				return hmac_hash_algos[i].value;
		}
		return PSA_ALG_NONE;
	}

	/* Try CMAC modes */
	cmac_algos = get_cmac_algo_mappings();
	cmac_count = get_cmac_algo_mappings_count();
	for (i = 0; i < cmac_count; i++) {
		if (cmac_algos[i].name &&
		    !strcasecmp(algo_str, cmac_algos[i].name))
			return cmac_algos[i].value;
	}

	/* Try AEAD */
	aead_algos = get_aead_algo_mappings();
	aead_count = get_aead_algo_mappings_count();
	for (i = 0; i < aead_count; i++) {
		if (aead_algos[i].name &&
		    !strcasecmp(algo_str, aead_algos[i].name))
			return aead_algos[i].value;
	}

	/* Try cipher */
	cipher_algos = get_cipher_algo_mappings();
	cipher_count = get_cipher_algo_mappings_count();
	for (i = 0; i < cipher_count; i++) {
		if (cipher_algos[i].name &&
		    !strcasecmp(algo_str, cipher_algos[i].name))
			return cipher_algos[i].value;
	}

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

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return PSA_ALG_NONE;

	/* PSA supports only one algorithm per key, take the first */
	token = strtok_r(algo_copy, ",", &saveptr);
	if (token)
		algorithm = parse_psa_single_algorithm(token, key_type);

	free(algo_copy);
	return algorithm;
}

/**
 * @brief Log PSA key generation parameters
 *
 * @param attributes Pointer to PSA key attributes
 * @param key_id Key identifier
 */
static void log_psa_keygen_params(const psa_key_attributes_t *attributes,
				  psa_key_id_t key_id)
{
	LOG_INFO("=== psa_generate_key Parameters ===");
	LOG_INFO("  key_id: 0x%08x (%u)", key_id, key_id);
	LOG_INFO("  key_type: %u (%s)", psa_get_key_type(attributes),
		 key_type_to_string(psa_get_key_type(attributes)));
	LOG_INFO("  key_bits: %zu", psa_get_key_bits(attributes));
	LOG_INFO("  algorithm: 0x%08x", psa_get_key_algorithm(attributes));
	LOG_INFO("  usage_flags: 0x%08x", psa_get_key_usage_flags(attributes));
	LOG_INFO("  lifetime: 0x%08x", psa_get_key_lifetime(attributes));
	LOG_INFO("====================================");
}

/**
 * @brief Append a usage string to a buffer
 *
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param written Pointer to number of bytes already written
 * @param usage string to append
 */
static void append_usage_str(char *buffer, size_t buffer_size, size_t *written,
			     const char *usage)
{
	int ret = 0;

	if (*written > 0 && *written < buffer_size) {
		ret = snprintf(buffer + *written, buffer_size - *written, ", ");
		if (ret > 0 && (size_t)ret < buffer_size - *written)
			*written += ret;
	}

	if (*written < buffer_size) {
		ret = snprintf(buffer + *written, buffer_size - *written, "%s",
			       usage);
		if (ret > 0 && (size_t)ret < buffer_size - *written)
			*written += ret;
	}
}

/**
 * @brief Convert usage flags to string
 *
 * @param usage_flags PSA key usage flags
 * @param buffer Output buffer for usage string
 * @param buffer_size Size of output buffer
 */
static void usage_flags_to_string(psa_key_usage_t usage_flags, char *buffer,
				  size_t buffer_size)
{
	size_t written = 0;

	if (!buffer || !buffer_size)
		return;

	buffer[0] = '\0';

	if (usage_flags & PSA_KEY_USAGE_ENCRYPT)
		append_usage_str(buffer, buffer_size, &written, "encrypt");

	if (usage_flags & PSA_KEY_USAGE_DECRYPT)
		append_usage_str(buffer, buffer_size, &written, "decrypt");

	if (usage_flags & PSA_KEY_USAGE_SIGN_MESSAGE)
		append_usage_str(buffer, buffer_size, &written, "sign");

	if (usage_flags & PSA_KEY_USAGE_VERIFY_MESSAGE)
		append_usage_str(buffer, buffer_size, &written, "verify");

	if (usage_flags & PSA_KEY_USAGE_SIGN_HASH)
		append_usage_str(buffer, buffer_size, &written, "sign_hash");

	if (usage_flags & PSA_KEY_USAGE_VERIFY_HASH)
		append_usage_str(buffer, buffer_size, &written, "verify_hash");

	if (!written && buffer_size > 0)
		SNPRINTF(buffer, buffer_size, "none");
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
 * @param key_id Generated key identifier
 * @param attributes Pointer to key attributes
 * @param transient Whether key is transient (volatile)
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

	/* Get the actual algorithm set in the key */
	actual_algo = psa_get_key_algorithm(attributes);
	algo_name = psa_algorithm_to_string(actual_algo);

	printf("\n");
	printf("Symmetric key generated successfully\n");
	printf("====================================\n");
	printf("ID: 0x%08x (%u) | Type: %s | Size: %zu bits\n", key_id, key_id,
	       key_type_to_string(psa_get_key_type(attributes)),
	       psa_get_key_bits(attributes));
	printf("Usage: %s\n", usage_str);
	printf("Permitted algo: %s\n", algo_name);
	printf("Persistence: %s\n", transient ? "transient" : "persistent");
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

	/* Print common options */
	cli_keygen_sym_help_common();

	printf("\nNotes for PSA:\n");
	printf("  - PSA supports only ONE algorithm per key (first one is used)\n");

	printf("\nExamples:\n");
	printf("  %s keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt -i 1\n",
	       prog_name);
	printf("  %s keygen-sym -t HMAC -s 256 -a SHA256 -u sign,verify -i 0x12345678\n\n",
	       prog_name);
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

	LOG_INFO("Symmetric key generation operation (PSA API)");

	/* Parse key type */
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

	/* Parse permitted algorithm (PSA takes only first one) */
	algorithm = parse_psa_permitted_algo(args->op.keygen.permitted_algo,
					     args->op.keygen.key_type);
	if (algorithm == PSA_ALG_NONE) {
		LOG_ERROR("Invalid permitted algorithm: %s",
			  args->op.keygen.permitted_algo);
		goto cleanup;
	}

	/* Parse usage flags */
	usage_flags = parse_psa_usage_flags(args->op.keygen.usage);
	if (!usage_flags) {
		LOG_ERROR("Invalid or empty usage flags: %s",
			  args->op.keygen.usage);
		goto cleanup;
	}

	/* Setup key attributes */
	psa_set_key_type(&attributes, key_type);
	psa_set_key_bits(&attributes, args->op.keygen.key_size);
	psa_set_key_algorithm(&attributes, algorithm);
	psa_set_key_usage_flags(&attributes, usage_flags);

	/* Set lifetime (transient or persistent) */
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
