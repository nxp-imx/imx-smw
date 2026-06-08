// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw/names.h>
#include <smw_crypto.h>
#include <smw_keymgr.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "parser_encrypt.h"
#include "smw_cipher_mapping_generated.h"
#include "utils.h"

/**
 * @brief Display help information for encryption (SMW API)
 */
void cli_encrypt_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Encrypt Operation - SMW API\n\n");

	printf("Usage: %s encrypt [OPTIONS]\n\n", prog_name);
	printf("Encrypt data using a generated key.\n\n");

	/* Print common options */
	cli_encrypt_help_common();

	/* SMW-specific option */
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Symmetric Examples:\n");
	printf("  %s encrypt -a AES-CBC -k 1 --iv 000102030405060708090a0b0c0d0e0f",
	       prog_name);
	printf(" -i plain.bin -o enc.bin\n");
	printf("  %s encrypt -a AES-CTR -k 1 --iv 00112233445566778899aabbccddeeff -i data.bin\n\n",
	       prog_name);

	printf("Asymmetric Examples:\n");
	printf("  %s encrypt -a RSA-OAEP-SHA256 -k 2 -i plain.bin -o enc.bin\n",
	       prog_name);
	printf("  %s encrypt -a RSA-OAEP-SHA256 -k 2 --salt aabbccdd -i plain.bin -o enc.bin\n\n",
	       prog_name);
}

/**
 * @brief Display help information for decryption (SMW API)
 */
void cli_decrypt_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Decrypt Operation - SMW API\n\n");
	printf("Usage: %s decrypt [OPTIONS]\n\n", prog_name);
	printf("Decrypt data using a generated key.\n\n");

	/* Print common options */
	cli_encrypt_help_common();

	/* SMW-specific option */
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Symmetric Examples:\n");
	printf("  %s decrypt -a AES-CBC -k 1 --iv 000102030405060708090a0b0c0d0e0f",
	       prog_name);
	printf(" -i enc.bin -o dec.bin\n");
	printf("  %s decrypt -a AES-CTR -k 1 --iv 00112233445566778899aabbccddeeff -i enc.bin\n\n",
	       prog_name);

	printf("Asymmetric Examples:\n");
	printf("  %s decrypt -a RSA-OAEP-SHA256 -k 2 -i enc.bin -o dec.bin\n",
	       prog_name);
	printf("  %s decrypt -a RSA-OAEP-SHA256 -k 2 --salt aabbccdd -i enc.bin -o dec.bin\n\n",
	       prog_name);
}

/**
 * @brief Log SMW cipher operation parameters for debugging
 *
 * @param cipher_args  Pointer to the SMW cipher arguments structure
 * @param encrypt      true for encryption, false for decryption
 */
static void log_smw_cipher_params(const struct smw_cipher_args *cipher_args,
				  bool encrypt)
{
	if (!cipher_args)
		return;

	LOG_INFO("=== smw_cipher Parameters ===");
	LOG_INFO("  direction: %s", encrypt ? "ENCRYPT" : "DECRYPT");
	LOG_INFO("  init.version: %u", cipher_args->init.version);
	LOG_INFO("  init.subsystem_name: %s",
		 cli_smw_get_subsystem_name(cipher_args->init.subsystem_name));
	LOG_INFO("  init.mode_name: %u", cipher_args->init.mode_name);
	LOG_INFO("  init.op_type_name: %u", cipher_args->init.op_type_name);
	LOG_INFO("  init.iv: %p", (void *)cipher_args->init.iv);
	LOG_INFO("  init.iv_length: %u", cipher_args->init.iv_length);
	LOG_INFO("  init.nb_keys: %u", cipher_args->init.nb_keys);
	LOG_INFO("  data.input: %p", (void *)cipher_args->data.input);
	LOG_INFO("  data.input_length: %u", cipher_args->data.input_length);
	LOG_INFO("  data.output: %p", (void *)cipher_args->data.output);
	LOG_INFO("  data.output_length: %u", cipher_args->data.output_length);
	LOG_INFO("=============================");
}

/**
 * @brief Execute a cipher encrypt or decrypt operation using the SMW API
 *
 * Maps the CLI cipher algorithm to SMW cipher mode and key type using
 * auto-generated tables, sets up the SMW cipher arguments, and calls
 * the SMW one-shot cipher API.
 *
 * @param args     Parsed command-line options
 * @param encrypt  true for encryption, false for decryption
 */
static enum cli_exit_code cipher_execute(struct parsed_options *args,
					 bool encrypt)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	unsigned char *iv = NULL;
	size_t input_size = 0;
	size_t output_size = 0;
	size_t iv_len = 0;
	struct smw_cipher_args cipher_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_key_descriptor *keys_desc_array[1] = { &key_desc };
	smw_cipher_mode_t smw_mode = SMW_CIPHER_MODE_NAME_NONE;
	smw_key_type_t smw_key_type = SMW_KEY_TYPE_NAME_NONE;
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	const char *direction_str = encrypt ? "encrypt" : "decrypt";

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	if (!args->input_filename) {
		LOG_ERROR("Missing input filename");
		goto cleanup;
	}

	LOG_INFO("Cipher %s operation started (SMW API)", direction_str);
	LOG_VERBOSE("  algo           : %d", args->op.cipher.algo);
	LOG_VERBOSE("  key_id         : 0x%08x (%u)", args->key_id,
		    args->key_id);
	LOG_VERBOSE("  iv_hex         : %s",
		    args->op.cipher.iv_hex ? args->op.cipher.iv_hex : "(none)");
	LOG_VERBOSE("  input_filename : %s", args->input_filename);
	LOG_VERBOSE("  output_filename: %s",
		    args->output_filename ? args->output_filename : "(stdout)");
	LOG_VERBOSE("  subsystem      : %s",
		    cli_smw_get_subsystem_name(args->subsystem));

	/* Map CLI algorithm to SMW cipher mode */
	LOG_VERBOSE("Mapping CLI algorithm to SMW cipher mode: %d",
		    args->op.cipher.algo);
	smw_mode = get_smw_cipher_mode(args->op.cipher.algo);
	if (smw_mode == SMW_CIPHER_MODE_NAME_NONE) {
		LOG_ERROR("Unsupported cipher mode: %d", args->op.cipher.algo);
		goto cleanup;
	}

	LOG_VERBOSE("SMW cipher mode resolved: %u", smw_mode);

	/* Map CLI algorithm to SMW key type */
	LOG_VERBOSE("Mapping CLI algorithm to SMW key type: %d",
		    args->op.cipher.algo);
	smw_key_type = get_smw_cipher_key_type(args->op.cipher.algo);
	if (smw_key_type == SMW_KEY_TYPE_NAME_NONE) {
		LOG_ERROR("Unsupported key type for algorithm: %d",
			  args->op.cipher.algo);
		goto cleanup;
	}

	LOG_VERBOSE("SMW key type resolved: %u", smw_key_type);

	/* Parse IV from hex string (if provided) */
	if (args->op.cipher.iv_hex) {
		LOG_VERBOSE("Parsing IV hex string: %s",
			    args->op.cipher.iv_hex);
		if (util_hex_string_to_bytes(args->op.cipher.iv_hex, &iv,
					     &iv_len)) {
			LOG_ERROR("Failed to parse IV hex string");
			goto cleanup;
		}

		if (iv_len > UINT32_MAX) {
			LOG_ERROR("IV length %zu exceeds maximum supported size",
				  iv_len);
			goto cleanup;
		}

		LOG_VERBOSE("IV parsed: %zu bytes", iv_len);
	} else {
		LOG_VERBOSE("No IV provided");
	}

	/* Read input file */
	LOG_VERBOSE("Reading input file: %s", args->input_filename);
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	LOG_VERBOSE("Input file read successfully: %zu bytes", input_size);

	if (input_size > UINT32_MAX) {
		LOG_ERROR("Input size too large for SMW API: %zu", input_size);
		goto cleanup;
	}

	/*
	 * Allocate output buffer.
	 * Add a cipher block margin (16 bytes for AES, 8 for DES3)
	 * to handle potential padding in the output.
	 */
	output_size = input_size + 16;

	if (output_size > UINT32_MAX) {
		LOG_ERROR("Output size too large for SMW API: %zu",
			  output_size);
		goto cleanup;
	}

	LOG_VERBOSE("Allocating output buffer: %zu bytes", output_size);
	output = util_alloc_buffer(output_size, "cipher output");
	if (!output)
		goto cleanup;

	/* Setup key descriptor - reference key by ID */
	LOG_VERBOSE("Setting up key descriptor: id=0x%08x, type=%u",
		    args->key_id, smw_key_type);
	key_desc.id = args->key_id;
	key_desc.type_name = smw_key_type;

	/*
	 * Setup SMW cipher arguments following the test engine pattern:
	 *   cipher_args.init  = initialization parameters
	 *   cipher_args.data  = input/output data buffers
	 */
	cipher_args.init.version = 0;
	cipher_args.init.mode_name = smw_mode;
	cipher_args.init.op_type_name =
		encrypt ? SMW_CIPHER_OP_TYPE_NAME_ENCRYPT :
			  SMW_CIPHER_OP_TYPE_NAME_DECRYPT;
	cipher_args.init.iv = iv;
	cipher_args.init.iv_length = iv_len;
	cipher_args.init.keys_desc = keys_desc_array;
	cipher_args.init.nb_keys = 1;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE) {
		LOG_VERBOSE("Forcing subsystem: %s",
			    cli_smw_get_subsystem_name(args->subsystem));
		cipher_args.init.subsystem_name = args->subsystem;
	}

	cipher_args.data.version = 0;
	cipher_args.data.input = input;
	cipher_args.data.input_length = input_size;
	cipher_args.data.output = output;
	cipher_args.data.output_length = output_size;

	log_smw_cipher_params(&cipher_args, encrypt);

	/* Call SMW one-shot cipher API */
	LOG_VERBOSE("Calling smw_cipher()");
	status = smw_cipher(&cipher_args);
	if (!is_smw_api_success("smw_cipher", status)) {
		if (status == SMW_STATUS_OUTPUT_TOO_SHORT)
			LOG_ERROR("Output buffer too short, need %u bytes",
				  cipher_args.data.output_length);
		goto cleanup;
	}

	if (encrypt)
		SUCCESS("Symmetric Encryption");
	else
		SUCCESS("Symmetric Decryption");

	/* Use the actual output length returned by SMW */
	output_size = cipher_args.data.output_length;
	LOG_VERBOSE("Output length: %zu bytes", output_size);

	/* Write output */
	LOG_VERBOSE("Writing output data");
	if (util_write_output_data(output, output_size, args->output_filename,
				   false)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (input)
		free(input);

	if (output)
		free(output);

	if (iv)
		free(iv);

	return ret;
}

/**
 * @brief Execute the encrypt operation using the SMW API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_encrypt_operation(struct parsed_options *args)
{
	return cipher_execute(args, true);
}

/**
 * @brief Execute the decrypt operation using the SMW API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_decrypt_operation(struct parsed_options *args)
{
	return cipher_execute(args, false);
}
