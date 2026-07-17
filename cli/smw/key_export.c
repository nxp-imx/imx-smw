// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <smw_keymgr.h>
#include <smw_status.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "parser_key_export.h"
#include "pubkey_encode.h"
#include "smw_asym_key_mappings_generated.h"
#include "utils.h"

#define GET_FILE_SIZE(path) util_get_file_size_by_path((path))

/**
 * @brief Log SMW key export operation parameters
 *
 * @param args Pointer to SMW export key arguments structure
 * @param key_buffer Pointer to keypair buffer with allocated buffers
 * @param is_rsa true if the key is RSA type
 */
static void
log_smw_key_export_params(const struct smw_export_key_args *args,
			  const struct smw_keypair_buffer *key_buffer,
			  bool is_rsa)
{
	if (!args || !args->key_descriptor)
		return;

	LOG_INFO("=== smw_export_key Parameters (smw_export_key_args) ===");
	LOG_INFO("  version:          %u", args->version);
	LOG_INFO("  key_id:           0x%08x (%u)", args->key_descriptor->id,
		 args->key_descriptor->id);

	if (!key_buffer)
		goto end;

	if (is_rsa) {
		LOG_INFO("  key_format:       RSA");
		LOG_INFO("  public_data:      %p",
			 (void *)key_buffer->rsa.public_data);
		LOG_INFO("  public_length:    %u",
			 key_buffer->rsa.public_length);
		LOG_INFO("  modulus:          %p",
			 (void *)key_buffer->rsa.modulus);
		LOG_INFO("  modulus_length:   %u",
			 key_buffer->rsa.modulus_length);
	} else {
		LOG_INFO("  key_format:       Generic");
		LOG_INFO("  public_data:      %p",
			 (void *)key_buffer->gen.public_data);
		LOG_INFO("  public_length:    %u",
			 key_buffer->gen.public_length);
	}

end:
	LOG_INFO("=======================================================");
}

/**
 * @brief Print key export result summary
 *
 * @param key_id Exported key ID
 * @param key_buffer Keypair buffer with exported data
 * @param pub_file Public key output file
 * @param is_rsa true if the key is RSA type
 * @param data_length Number of bytes written to output file
 */
static void print_export_result(unsigned int key_id,
				const struct smw_keypair_buffer *key_buffer,
				const char *pub_file, bool is_rsa,
				size_t data_length)
{
	SUCCESS("Key export");
	INFO("Key ID", "0x%08x (%u)", key_id, key_id);
	if (is_rsa) {
		if (pub_file && key_buffer->rsa.modulus)
			INFO("RSA modulus", "%s (%zu bytes)", pub_file,
			     data_length);
	} else {
		if (pub_file && key_buffer->gen.public_data)
			INFO("Public key", "%s (%zu bytes)", pub_file,
			     data_length);
	}
	printf("\n");
}

/**
 * @brief Allocate public key buffers for generic (ECC/Edwards) keys
 *
 * @param key_buffer Keypair buffer to allocate
 */
static int alloc_gen_public(struct smw_keypair_buffer *key_buffer)
{
	if (!key_buffer->gen.public_length) {
		LOG_ERROR("The key has no public component");
		return -1;
	}

	key_buffer->gen.public_data = calloc(1, key_buffer->gen.public_length);
	if (!key_buffer->gen.public_data) {
		LOG_ERROR("Failed to allocate public key buffer");
		return -1;
	}

	return 0;
}

/**
 * @brief Allocate public key buffers for RSA keys (modulus + public exponent)
 *
 * @param key_buffer Keypair buffer to allocate
 */
static int alloc_rsa_public(struct smw_keypair_buffer *key_buffer)
{
	if (!key_buffer->rsa.modulus_length) {
		LOG_ERROR("RSA modulus length is 0");
		return -1;
	}

	key_buffer->rsa.modulus = calloc(1, key_buffer->rsa.modulus_length);
	if (!key_buffer->rsa.modulus) {
		LOG_ERROR("Failed to allocate RSA modulus buf");
		return -1;
	}

	if (key_buffer->rsa.public_length > 0) {
		key_buffer->rsa.public_data =
			calloc(1, key_buffer->rsa.public_length);
		if (!key_buffer->rsa.public_data) {
			LOG_ERROR("Failed to allocate RSA public exponent buf");
			return -1;
		}
	}

	return 0;
}

/**
 * @brief Resolve key type name and security size from SMW key descriptor
 *
 * @param key_desc       SMW key descriptor (id must be set)
 * @param key_type_name  Output resolved key type name string
 */
static int resolve_key_type(struct smw_key_descriptor *key_desc,
			    const char **key_type_name)
{
	enum smw_status_code status = SMW_STATUS_OK;

	status = smw_get_key_type_name(key_desc);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_get_key_type_name", status))
			return -1;
	}

	status = smw_get_security_size(key_desc);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_get_security_size", status))
			return -1;
	}

	*key_type_name = asym_key_type_to_string(key_desc->type_name);
	if (!*key_type_name || !strcasecmp(*key_type_name, "UNKNOWN")) {
		LOG_ERROR("Cannot resolve SMW key type %d to string",
			  (int)key_desc->type_name);
		return -1;
	}

	return 0;
}

/**
 * @brief Display help information for key export (SMW API)
 */
void cli_key_export_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Key Export Operation - SMW API\n\n");

	cli_key_export_help_common();

	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Examples:\n");
	printf("  %s key-export -i 1 -o pub_key.bin\n", prog_name);
	printf("  %s key-export -i 1 -o pub_key.der --der\n\n", prog_name);
}

/**
 * @brief Execute key export using SMW API
 *
 * Exports the public key material using smw_export_key() after querying
 * the required buffer sizes with smw_get_key_buffers_lengths().
 *
 * For RSA keys, the modulus is written to the public key output file.
 * For generic keys (ECC, Edwards), the public point is written.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_key_export_operation(struct parsed_options *args)
{
	struct smw_keypair_buffer key_buffer = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_export_key_args export_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	size_t data_length = 0;
	size_t raw_len = 0;
	bool is_rsa = false;
	bool want_pem = false;
	const char *key_type_name = NULL;
	const uint8_t *raw_data = NULL;
	unsigned char *pub_data_to_free = NULL;
	unsigned char *modulus_to_free = NULL;
	FILE *f = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("Key export operation (SMW API)");

	if (!args->op.key_export.key_file) {
		LOG_ERROR("No output file specified.");
		goto cleanup;
	}

	/* Set up key descriptor with the given key ID */
	key_desc.id = args->op.key_export.key_id;
	key_desc.buffer = &key_buffer;

	if (resolve_key_type(&key_desc, &key_type_name))
		goto cleanup;

	is_rsa = (key_type_name && !strcasecmp(key_type_name, "RSA"));

	/* Query the subsystem for the required buffer lengths */
	status = smw_get_key_buffers_lengths(&key_desc);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_get_key_buffers_lengths", status))
			goto cleanup;
	}

	/* Allocate public key buffers based on key type */
	if (is_rsa) {
		if (alloc_rsa_public(&key_buffer))
			goto cleanup;
		pub_data_to_free = key_buffer.rsa.public_data;
		modulus_to_free = key_buffer.rsa.modulus;
	} else {
		if (alloc_gen_public(&key_buffer))
			goto cleanup;
		pub_data_to_free = key_buffer.gen.public_data;
	}

	/* Call smw_export_key() */
	export_args.version = 0;
	export_args.key_descriptor = &key_desc;

	log_smw_key_export_params(&export_args, &key_buffer, is_rsa);

	status = smw_export_key(&export_args);
	if (status != SMW_STATUS_OK) {
		if (!is_smw_api_success("smw_export_key", status))
			goto cleanup;
	}

	if (args->op.key_export.use_der || args->op.key_export.use_pem) {
		want_pem = args->op.key_export.use_pem;

		if (is_rsa) {
			ret = pubkey_encode_rsa(key_desc.security_size,
						key_buffer.rsa.modulus,
						key_buffer.rsa.modulus_length,
						key_buffer.rsa.public_data,
						key_buffer.rsa.public_length,
						args->op.key_export.key_file,
						want_pem);
		} else {
			ret = pubkey_encode(key_type_name,
					    key_desc.security_size,
					    key_buffer.gen.public_data,
					    key_buffer.gen.public_length,
					    args->op.key_export.key_file,
					    want_pem);
		}
		data_length = GET_FILE_SIZE(args->op.key_export.key_file);

		if (ret) {
			LOG_ERROR("Key format conversion failed");
			goto cleanup;
		}
	} else {
		/* Raw binary output */
		raw_data = is_rsa ? key_buffer.rsa.modulus :
				    key_buffer.gen.public_data;
		raw_len = is_rsa ? key_buffer.rsa.modulus_length :
				   key_buffer.gen.public_length;
		f = fopen(args->op.key_export.key_file, "wb");

		if (!f) {
			LOG_ERROR("Failed to open output file: %s",
				  args->op.key_export.key_file);
			goto cleanup;
		}

		if (fwrite(raw_data, 1, raw_len, f) != raw_len) {
			LOG_ERROR("Failed to write raw key to file");
			FCLOSE(f);
			goto cleanup;
		}

		FCLOSE(f);
		data_length = raw_len;
	}

	/* Print result summary */
	print_export_result(key_desc.id, &key_buffer,
			    args->op.key_export.key_file, is_rsa, data_length);

	ret = CLI_EXIT_SUCCESS;

cleanup:
	free(pub_data_to_free);
	free(modulus_to_free);

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
