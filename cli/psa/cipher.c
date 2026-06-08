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
#include "parser_encrypt.h"
#include "psa_cipher_mapping_generated.h"
#include "utils.h"

/**
 * @brief Display help information for encryption (PSA API)
 */
void cli_encrypt_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Encrypt Operation - PSA API\n\n");

	printf("Usage: %s encrypt [OPTIONS]\n\n", prog_name);
	printf("Encrypt data using a generated key.\n\n");

	cli_encrypt_help_common();

	printf("\nNote: The --iv option is accepted but ignored.\n\n");

	printf("Symmetric Examples:\n");
	printf("  %s encrypt -a AES-CBC -k 1 -i plain.bin -o enc.bin\n",
	       prog_name);
	printf("  %s encrypt -a AES-CTR -k 1 -i data.bin\n\n", prog_name);

	printf("Asymmetric Examples:\n");
	printf("  %s encrypt -a RSA-OAEP-SHA256 -k 2 -i plain.bin -o enc.bin\n",
	       prog_name);
	printf("  %s encrypt -a RSA-OAEP-SHA256 -k 2 --salt aabbccdd -i plain.bin -o enc.bin\n\n",
	       prog_name);
}

/**
 * @brief Display help information for decryption (PSA API)
 */
void cli_decrypt_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Decrypt Operation - PSA API\n\n");
	printf("Usage: %s decrypt [OPTIONS]\n\n", prog_name);
	printf("Decrypt data using a generated key.\n\n");

	cli_encrypt_help_common();

	printf("\nNote: The --iv option is accepted but ignored.\n\n");

	printf("Symmetric Examples:\n");
	printf("  %s decrypt -a AES-CBC -k 1 -i enc.bin -o dec.bin\n",
	       prog_name);
	printf("  %s decrypt -a AES-CTR -k 1 -i enc.bin\n\n", prog_name);

	printf("Asymmetric Examples:\n");
	printf("  %s decrypt -a RSA-OAEP-SHA256 -k 2 -i enc.bin -o dec.bin\n",
	       prog_name);
	printf("  %s decrypt -a RSA-OAEP-SHA256 -k 2 --salt aabbccdd -i enc.bin -o dec.bin\n\n",
	       prog_name);
}

/**
 * @brief Log PSA cipher operation parameters for debugging
 *
 * @param key           PSA key identifier
 * @param alg           PSA cipher algorithm
 * @param input         Pointer to input data buffer
 * @param input_length  Size of input data in bytes
 * @param output        Pointer to output data buffer
 * @param output_size   Size of output buffer in bytes
 * @param encrypt       true for encryption, false for decryption
 */
static void log_psa_cipher_params(psa_key_id_t key, psa_algorithm_t alg,
				  const uint8_t *input, size_t input_length,
				  uint8_t *output, size_t output_size,
				  bool encrypt)
{
	LOG_INFO("=== psa_cipher_%s Parameters ===",
		 encrypt ? "encrypt" : "decrypt");
	LOG_INFO("  key: %u", (unsigned int)key);
	LOG_INFO("  alg: %s (0x%08x)", get_psa_cipher_alg_name(alg),
		 (unsigned int)alg);
	LOG_INFO("  input: %p", (const void *)input);
	LOG_INFO("  input_length: %zu", input_length);
	LOG_INFO("  output: %p", (void *)output);
	LOG_INFO("  output_size: %zu", output_size);
	LOG_INFO("=====================================");
}

/**
 * @brief Execute a cipher encrypt or decrypt operation using the PSA API
 *
 * Maps the CLI cipher algorithm to PSA algorithm using auto-generated
 * tables and calls the PSA one-shot cipher API. The PSA API manages
 * IV internally: encrypt prepends a random IV to the output, decrypt
 * reads it from the beginning of the input.
 *
 * @param args     Parsed command-line options
 * @param encrypt  true for encryption, false for decryption
 */
static enum cli_exit_code cipher_execute(struct parsed_options *args,
					 bool encrypt)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	size_t input_size = 0;
	size_t output_size = 0;
	size_t output_length = 0;
	psa_key_id_t key = PSA_KEY_ID_NULL;
	psa_algorithm_t alg = PSA_ALG_NONE;
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	const char *direction_str = encrypt ? "encrypt" : "decrypt";
	const char *api_name = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	if (!args->input_filename) {
		LOG_ERROR("Missing input filename");
		goto cleanup;
	}

	LOG_INFO("Cipher %s operation started (PSA API)", direction_str);
	LOG_VERBOSE("  algo           : %d", args->op.cipher.algo);
	LOG_VERBOSE("  key_id         : 0x%08x (%u)", args->key_id,
		    args->key_id);
	LOG_VERBOSE("  iv_hex         : %s",
		    args->op.cipher.iv_hex ? args->op.cipher.iv_hex : "(none)");
	LOG_VERBOSE("  input_filename : %s", args->input_filename);
	LOG_VERBOSE("  output_filename: %s",
		    args->output_filename ? args->output_filename : "(stdout)");

	/* Map CLI algorithm to PSA algorithm */
	LOG_VERBOSE("Mapping CLI algorithm to PSA algorithm: %d",
		    args->op.cipher.algo);
	alg = get_psa_cipher_alg(args->op.cipher.algo);
	if (alg == PSA_ALG_NONE) {
		LOG_ERROR("Unsupported cipher algorithm: %d",
			  args->op.cipher.algo);
		goto cleanup;
	}

	LOG_VERBOSE("PSA algorithm resolved: %s (0x%08x)",
		    get_psa_cipher_alg_name(alg), (unsigned int)alg);

	key = (psa_key_id_t)args->key_id;

	/*
	 * PSA one-shot cipher API manages IV internally:
	 *   - Encrypt: random IV is generated and prepended to the output
	 *   - Decrypt: IV is read from the beginning of the input
	 * The --iv option is accepted by the parser but ignored here.
	 */
	if (args->op.cipher.iv_hex && alg != PSA_ALG_ECB_NO_PADDING) {
		LOG_VERBOSE("IV hex provided but ignored by PSA API");
	}

	/* Read input file */
	LOG_VERBOSE("Reading input file: %s", args->input_filename);
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	LOG_VERBOSE("Input file read successfully: %zu bytes", input_size);

	/*
	 * Allocate output buffer using PSA macros.
	 * Encrypt output includes IV prefix (except ECB).
	 * Decrypt output is plaintext only.
	 */
	if (encrypt)
		output_size = PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_size);
	else
		output_size = PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_size);

	if (!output_size)
		output_size = input_size + 16;

	LOG_VERBOSE("Allocating output buffer: %zu bytes", output_size);
	output = util_alloc_buffer(output_size, "cipher output");
	if (!output)
		goto cleanup;

	log_psa_cipher_params(key, alg, input, input_size, output, output_size,
			      encrypt);

	/* Call PSA cipher API */
	if (encrypt) {
		api_name = "psa_cipher_encrypt";
		LOG_VERBOSE("Calling psa_cipher_encrypt()");
		status = psa_cipher_encrypt(key, alg, input, input_size, output,
					    output_size, &output_length);
	} else {
		api_name = "psa_cipher_decrypt";
		LOG_VERBOSE("Calling psa_cipher_decrypt()");
		status = psa_cipher_decrypt(key, alg, input, input_size, output,
					    output_size, &output_length);
	}

	if (!is_psa_api_success(api_name, status)) {
		if (status == PSA_ERROR_BUFFER_TOO_SMALL)
			LOG_ERROR("Output buffer too small");
		goto cleanup;
	}

	SUCCESS("Symmetric Ciphering");

	LOG_VERBOSE("Output length: %zu bytes", output_length);

	/* Write output */
	LOG_VERBOSE("Writing output data");
	if (util_write_output_data(output, output_length, args->output_filename,
				   false)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (input)
		free(input);

	if (output)
		free(output);

	return ret;
}

/**
 * @brief Execute the encrypt operation using the PSA API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_encrypt_operation(struct parsed_options *args)
{
	return cipher_execute(args, true);
}

/**
 * @brief Execute the decrypt operation using the PSA API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_decrypt_operation(struct parsed_options *args)
{
	return cipher_execute(args, false);
}
