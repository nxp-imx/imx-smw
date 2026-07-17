// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "helper.h"
#include "logger.h"
#include "parser_key_export.h"
#include "psa_asym_key_mappings_generated.h"
#include "pubkey_encode.h"
#include "utils.h"

#define GET_FILE_SIZE(path) util_get_file_size_by_path((path))

/**
 * @brief Log PSA key export operation parameters
 *
 * @param key_id PSA key identifier
 * @param data Pointer to the output buffer
 * @param data_size Size of the output buffer in bytes
 */
static void log_psa_key_export_params(psa_key_id_t key_id, const uint8_t *data,
				      size_t data_size)
{
	LOG_INFO("=== psa_export_public_key Parameters ===");
	LOG_INFO("  key_id:      0x%08x (%u)", key_id, key_id);
	LOG_INFO("  data:        %p", (void *)data);
	LOG_INFO("  data_size:   %zu bytes", data_size);
	LOG_INFO("=========================================");
}

/**
 * @brief Print key export result summary
 *
 * @param key_id Exported key ID
 * @param data_length Actual exported data length in bytes
 * @param pub_file Public key output file
 */
static void print_export_result(psa_key_id_t key_id, size_t data_length,
				const char *pub_file)
{
	SUCCESS("Key export");
	INFO("Key ID", "0x%08x (%u)", key_id, key_id);
	INFO("Public key", "%s (%zu bytes)", pub_file, data_length);
	printf("\n");
}

/**
 * @brief Query the required buffer size for public key export
 *
 * @param key_id PSA key identifier
 * @param key_type Output key type
 * @param key_bits Output key size in bits
 * @param buffer Output pointer to allocated buffer
 * @param buffer_size Output size of allocated buffer
 */
static int query_and_alloc_export_buffer(psa_key_id_t key_id,
					 psa_key_type_t *key_type,
					 size_t *key_bits, uint8_t **buffer,
					 size_t *buffer_size)
{
	psa_status_t status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	size_t required_size = 0;

	status = psa_get_key_attributes(key_id, &attributes);
	if (status != PSA_SUCCESS) {
		if (!is_psa_api_success("psa_get_key_attributes", status))
			return -1;
	}

	*key_type = psa_get_key_type(&attributes);
	*key_bits = psa_get_key_bits(&attributes);

	psa_reset_key_attributes(&attributes);

	required_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(*key_type, *key_bits);
	if (!required_size) {
		LOG_ERROR("Cannot determine buffer size for key 0x%08x",
			  key_id);
		return -1;
	}

	LOG_INFO("Required export buffer size: %zu bytes", required_size);

	*buffer = calloc(1, required_size);
	if (!*buffer) {
		LOG_ERROR("Failed to allocate export buffer (%zu bytes)",
			  required_size);
		return -1;
	}

	*buffer_size = required_size;

	return 0;
}

/**
 * @brief Display help information for key export (PSA API)
 */
void cli_key_export_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Key Export Operation - PSA API\n\n");

	cli_key_export_help_common();

	printf("Examples:\n");
	printf("  %s key-export -i 1 -o pub_key.bin\n", prog_name);
	printf("  %s key-export -i 1 -o pub_key.der --der\n\n", prog_name);
}

/**
 * @brief Execute key export using PSA API
 *
 * Exports the public key using psa_export_public_key().
 * If --der is specified, the raw public key is wrapped into a DER
 * SubjectPublicKeyInfo structure using psa_encode_der().
 * If --pem is specified, the DER structure is further base64-encoded
 * and wrapped with PEM header/footer.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_key_export_operation(struct parsed_options *args)
{
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	psa_key_id_t key_id = 0;
	psa_key_type_t key_type = 0;
	uint8_t *pub_buffer = NULL;
	const char *type_str = NULL;
	size_t key_bits = 0;
	size_t pub_buffer_size = 0;
	size_t pub_data_length = 0;
	size_t data_length = 0;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Key export operation (PSA API)");

	key_id = (psa_key_id_t)args->op.key_export.key_id;

	if (!args->op.key_export.key_file) {
		LOG_ERROR("No output file specified.");
		goto cleanup;
	}

	if (query_and_alloc_export_buffer(key_id, &key_type, &key_bits,
					  &pub_buffer, &pub_buffer_size))
		goto cleanup;

	log_psa_key_export_params(key_id, pub_buffer, pub_buffer_size);

	status = psa_export_public_key(key_id, pub_buffer, pub_buffer_size,
				       &pub_data_length);
	if (!is_psa_api_success("psa_export_public_key", status))
		goto cleanup;

	if (args->op.key_export.use_der || args->op.key_export.use_pem) {
		type_str = psa_key_type_to_export_name(key_type, key_bits);

		if (!type_str) {
			LOG_ERROR("Unsupported key type for DER/PEM encoding");
			goto cleanup;
		}

		if (pubkey_encode(type_str, (unsigned int)key_bits, pub_buffer,
				  pub_data_length, args->op.key_export.key_file,
				  args->op.key_export.use_pem)) {
			LOG_ERROR("Key format conversion failed");
			goto cleanup;
		}
		data_length = GET_FILE_SIZE(args->op.key_export.key_file);
	} else {
		/* Raw binary output */
		FILE *f = fopen(args->op.key_export.key_file, "wb");

		if (!f) {
			LOG_ERROR("Failed to open output file: %s",
				  args->op.key_export.key_file);
			goto cleanup;
		}

		if (fwrite(pub_buffer, 1, pub_data_length, f) !=
		    pub_data_length) {
			LOG_ERROR("Failed to write raw key to file");
			FCLOSE(f);
			goto cleanup;
		}

		FCLOSE(f);
		data_length = pub_data_length;
	}

	print_export_result(key_id, data_length, args->op.key_export.key_file);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (pub_buffer) {
		memset(pub_buffer, 0, pub_buffer_size);
		free(pub_buffer);
	}

	if (args) {
		if (args->op.key_export.key_file) {
			free(args->op.key_export.key_file);
			args->op.key_export.key_file = NULL;
		}
		if (args->log_filename) {
			free(args->log_filename);
			args->log_filename = NULL;
		}
	}

	return ret;
}
