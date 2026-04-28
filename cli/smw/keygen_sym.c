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
#include "key_sym_mappings.h"
#include "keygen_common.h"
#include "logger.h"
#include "parser_keygen_sym.h"
#include "smw_sym_key_mappings_generated.h"
#include "utils.h"

#define KEY_ALGO_LENGTH		64
#define USAGE_STR_MAX_LEN	256
#define ALGO_STR_MAX_LEN	512
#define SMW_SYM_ENCR(key, mode)	     SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(key, mode)
#define SMW_SYM_HMAC(hash, mac) SMW_ATTR_ALGO_MAC_HMAC(hash, mac)
#define SMW_SYM_MAC(algo, mode, mac) SMW_ATTR_ALGO_MAC(algo, mode, mac)

/**
 * @brief Parse a single mode/hash and combine with key algorithm
 *
 * @param mode_str Single mode string (e.g., "CBC", "GCM", "SHA256")
 * @param key_type Key type string (e.g., "AES", "HMAC")
 */
static smw_attr_algo_t parse_single_mode(const char *mode_str,
					 const char *key_type)
{
	uint32_t mode_value = 0;
	uint32_t key_type_value = 0;
	smw_attr_algo_t key_algo = SMW_ATTR_ALGO_NONE;
	const struct algo_mapping *aead_algos = NULL;
	const struct algo_mapping *cmac_algos = NULL;
	size_t aead_count = 0;
	size_t cmac_count = 0;
	size_t i = 0;
	bool is_aead = false;
	bool is_mac = false;

	if (!mode_str || !key_type)
		return SMW_ATTR_ALGO_NONE;

	if (parse_key_type(key_type, &key_type_value))
		return SMW_ATTR_ALGO_NONE;

	if (parse_single_algorithm(mode_str, key_type_value, &mode_value))
		return SMW_ATTR_ALGO_NONE;

	if (!strcasecmp(key_type, "HMAC"))
		return SMW_SYM_HMAC((smw_attr_algo_t)mode_value, 0);

	/* Convert key type value to SMW algo attribute */
	key_algo = key_type_to_algo((smw_key_type_t)key_type_value);

	/* Determine whether mode is AEAD or cipher */
	aead_algos = get_aead_algo_mappings();
	aead_count = get_aead_algo_mappings_count();

	for (i = 0; i < aead_count; i++) {
		if (aead_algos[i].name &&
		    !strcasecmp(mode_str, aead_algos[i].name)) {
			is_aead = true;
			break;
		}
	}

	if (is_aead)
		return SMW_ATTR_ALGO_AEAD(key_algo, (smw_attr_algo_t)mode_value,
					  0);

	/* Determine whether mode is MAC (CMAC) */
	cmac_algos = get_cmac_algo_mappings();
	cmac_count = get_cmac_algo_mappings_count();

	for (i = 0; i < cmac_count; i++) {
		if (cmac_algos[i].name &&
		    !strcasecmp(mode_str, cmac_algos[i].name)) {
			is_mac = true;
			break;
		}
	}

	if (is_mac)
		return SMW_SYM_MAC(key_algo, (smw_attr_algo_t)mode_value, 0);

	return SMW_SYM_ENCR(key_algo, (smw_attr_algo_t)mode_value);
}

/**
 * @brief Parse multiple permitted algorithms from comma-separated string
 *
 * @param algo_str Comma-separated algorithm list (e.g., "CBC,GCM,CTR")
 * @param key_type Key type string (e.g., "AES", "HMAC")
 * @param permitted_algo Output combined permitted algorithm value
 */
static int parse_smw_permitted_algos_multi(const char *algo_str,
					   const char *key_type,
					   smw_attr_algo_t *permitted_algo)
{
	char *algo_copy = NULL;
	char *token = NULL;
	char *saveptr = NULL;
	smw_attr_algo_t combined_algo = 0;
	smw_attr_algo_t single_algo = 0;
	int ret = -1;

	if (!algo_str || !key_type || !permitted_algo)
		return -1;

	algo_copy = strdup(algo_str);
	if (!algo_copy)
		return -1;

	token = strtok_r(algo_copy, ",", &saveptr);
	while (token) {
		/* Parse this mode/hash */
		single_algo = parse_single_mode(token, key_type);
		if (!single_algo) {
			LOG_ERROR("Unknown mode/algorithm: %s for key type %s",
				  token, key_type);
			goto cleanup;
		}

		/* Combine using OR */
		combined_algo |= single_algo;

		token = strtok_r(NULL, ",", &saveptr);
	}

	if (!combined_algo) {
		LOG_ERROR("No valid algorithms parsed");
		goto cleanup;
	}

	*permitted_algo = combined_algo;
	ret = 0;

cleanup:
	free(algo_copy);
	return ret;
}

/**
 * @brief Append a matched algorithm name to output buffer
 *
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @param written Pointer to number of bytes already written
 * @param first Pointer to flag indicating first entry
 * @param name Algorithm name to append
 */
static void append_algo_str(char *buffer, size_t buffer_size, size_t *written,
			    bool *first, const char *name)
{
	int ret = 0;

	if (!name || *written >= buffer_size)
		return;

	ret = snprintf(buffer + *written, buffer_size - *written, "%s%s",
		       *first ? "" : ", ", name);

	if (ret > 0 && (size_t)ret < buffer_size - *written)
		*written += ret;

	*first = false;
}

/**
 * @brief Convert permitted algorithm to string representation
 *
 * @param permitted_algo Permitted algorithm from key attributes
 * @param key_algo Key algorithm
 * @param buffer Output buffer for algorithm string
 * @param buffer_size Size of output buffer
 */
static void permitted_algo_to_string(smw_attr_algo_t permitted_algo,
				     smw_attr_algo_t key_algo, char *buffer,
				     size_t buffer_size)
{
	const struct algo_mapping *cipher_algos = NULL;
	const struct algo_mapping *aead_algos = NULL;
	const struct algo_mapping *hash_algos = NULL;
	const struct algo_mapping *cmac_algos = NULL;
	size_t count = 0;
	size_t i = 0;
	size_t written = 0;
	bool first = true;
	smw_attr_algo_t test_algo = 0;

	if (!buffer || !buffer_size)
		return;

	buffer[0] = '\0';

	/* For HMAC, show hash algorithms */
	if (key_algo == SMW_ATTR_ALGO_HMAC) {
		hash_algos = get_hmac_hash_algo_mappings();
		count = get_hmac_hash_algo_mappings_count();

		for (i = 0; i < count; i++) {
			test_algo = SMW_SYM_HMAC(hash_algos[i].value, 0);
			if ((permitted_algo & test_algo) == test_algo)
				append_algo_str(buffer, buffer_size, &written,
						&first, hash_algos[i].name);
		}
		return;
	}

	/* Check MAC modes (CMAC) */
	cmac_algos = get_cmac_algo_mappings();
	count = get_cmac_algo_mappings_count();

	for (i = 0; i < count; i++) {
		test_algo =
			SMW_SYM_MAC(key_algo,
				    (smw_attr_algo_t)cmac_algos[i].value, 0);
		if ((permitted_algo & test_algo) == test_algo)
			append_algo_str(buffer, buffer_size, &written, &first,
					cmac_algos[i].name);
	}

	/* Check AEAD modes */
	aead_algos = get_aead_algo_mappings();
	count = get_aead_algo_mappings_count();

	for (i = 0; i < count; i++) {
		test_algo =
			SMW_ATTR_ALGO_AEAD(key_algo, aead_algos[i].value, 0);
		if ((permitted_algo & test_algo) == test_algo)
			append_algo_str(buffer, buffer_size, &written, &first,
					aead_algos[i].name);
	}

	/* Check cipher modes */
	cipher_algos = get_cipher_algo_mappings();
	count = get_cipher_algo_mappings_count();

	for (i = 0; i < count; i++) {
		test_algo = SMW_SYM_ENCR(key_algo, cipher_algos[i].value);
		if ((permitted_algo & test_algo) == test_algo)
			append_algo_str(buffer, buffer_size, &written, &first,
					cipher_algos[i].name);
	}

	if (!written && buffer_size > 0)
		SNPRINTF(buffer, buffer_size, "none");
}

/**
 * @brief Print key generation result
 *
 * @param key_desc Pointer to key descriptor with generated key info
 * @param transient Whether key is transient
 * @param sensitive Whether key is sensitive
 */
static void print_key_result(const struct smw_key_descriptor *key_desc,
			     bool transient, bool sensitive)
{
	char usage_str[USAGE_STR_MAX_LEN] = { 0 };
	char algo_str[ALGO_STR_MAX_LEN] = { 0 };

	usage_flags_to_string(key_desc->attributes.usage_flags, usage_str,
			      sizeof(usage_str));

	permitted_algo_to_string(key_desc->attributes.permitted_algo,
				 key_type_to_algo(key_desc->type_name),
				 algo_str, sizeof(algo_str));

	printf("\n");
	printf("Symmetric key generated successfully\n");
	printf("====================================\n");
	printf("ID: 0x%08x (%u) | Type: %s | Size: %u bits\n", key_desc->id,
	       key_desc->id, key_type_to_string(key_desc->type_name),
	       key_desc->security_size);
	printf("Usage: %s\n", usage_str);
	printf("Permitted algo: %s\n", algo_str);
	printf("Persistence: %s | Sensitive: %s\n",
	       transient ? "transient" : "persistent",
	       sensitive ? "yes" : "no");
	printf("\n");
}

/**
 * @brief Display help information for symmetric key generation (SMW API)
 */
void cli_keygen_sym_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Symmetric Key Generation Operation - SMW API\n\n");

	/* Print common options */
	cli_keygen_sym_help_common();

	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("\nExamples:\n");
	printf("  %s keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt -i 1\n",
	       prog_name);
	printf("  %s keygen-sym -t HMAC -s 256 -a SHA256 -u sign,verify -i 0x12345678\n\n",
	       prog_name);
}

/**
 * @brief Execute symmetric key generation using SMW API
 *
 * Generates a symmetric cryptographic key using smw_generate_key() and
 * displays the key properties.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_keygen_sym_operation(struct parsed_options *args)
{
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_key_attributes key_attrs = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	smw_key_type_t key_type = SMW_KEY_TYPE_NAME_NONE;
	smw_attr_algo_t permitted_algo = 0;
	smw_attr_usage_t usage_flags = 0;
	struct smw_key_info key_info = { 0 };
	uint32_t kt_value = 0;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Symmetric key generation operation (SMW API)");

	/* Parse key type */
	if (parse_key_type(args->op.keygen.key_type, &kt_value)) {
		LOG_ERROR("Invalid key type: %s", args->op.keygen.key_type);
		goto cleanup;
	}

	if (kt_value >= (uint32_t)SMW_KEY_TYPE_NAME_NB) {
		LOG_ERROR("Key type value %u out of range for SMW key type",
			  kt_value);
		goto cleanup;
	}

	key_type = (smw_key_type_t)kt_value;

	/* Parse permitted algorithms (supports multiple comma-separated) */
	if (parse_smw_permitted_algos_multi(args->op.keygen.permitted_algo,
					    args->op.keygen.key_type,
					    &permitted_algo)) {
		LOG_ERROR("Invalid permitted algorithm(s): %s",
			  args->op.keygen.permitted_algo);
		goto cleanup;
	}

	/* Parse usage flags */
	usage_flags = parse_smw_usage_flags(args->op.keygen.usage);
	if (!usage_flags) {
		LOG_ERROR("Invalid or empty usage flags: %s",
			  args->op.keygen.usage);
		goto cleanup;
	}

	/* Setup key attributes */
	memset(&key_attrs, 0, sizeof(key_attrs));
	key_attrs.permitted_algo = permitted_algo;
	key_attrs.usage_flags = usage_flags;
	key_attrs.storage_id = 0;

	/* Set persistence */
	if (args->op.keygen.transient)
		key_attrs.attributes =
			SMW_ATTR_SET_TRANSIENT(key_attrs.attributes);
	else
		key_attrs.attributes =
			SMW_ATTR_SET_PERSISTENT(key_attrs.attributes);

	/* Set sensitivity */
	if (args->op.keygen.non_sensitive)
		key_attrs.attributes =
			SMW_ATTR_CLEAR_SENSITIVE(key_attrs.attributes);
	else
		key_attrs.attributes =
			SMW_ATTR_SET_SENSITIVE(key_attrs.attributes);

	/* Setup key descriptor */
	key_desc.type_name = key_type;
	key_desc.security_size = args->op.keygen.key_size;
	key_desc.id = args->op.keygen.key_id;
	key_desc.buffer = NULL;
	key_desc.attributes = key_attrs;

	/* Setup generation arguments */
	gen_args.version = 0;
	gen_args.key_descriptor = &key_desc;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE)
		gen_args.subsystem_name = args->subsystem;

	/* Check capability before attempting generation */
	key_info.key_type_name = key_type;
	key_info.security_size = args->op.keygen.key_size;

	status = smw_config_check_generate_key(gen_args.subsystem_name,
					       &key_info);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_config_check_generate_key",
					status))
			goto cleanup;
	}

	/* Log parameters */
	log_smw_keygen_params(&gen_args);

	/* Call SMW key generation API */
	status = smw_generate_key(&gen_args);
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		is_smw_api_success("smw_generate_key", status);
		goto cleanup;
	}

	/* Log warning if policy was ignored */
	if (status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		printf("\nWarning: Key generated successfully,");
		printf(" but some policy elements were ignored\n");
	}

	/* Print result */
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
