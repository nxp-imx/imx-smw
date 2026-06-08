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
#include "asym_enc_algo_generated.h"
#include "common.h"
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "psa_asym_enc_mapping_generated.h"
#include "utils.h"

/**
 * @brief Log PSA asymmetric encryption parameters for debugging
 *
 * @param key           PSA key identifier
 * @param alg           PSA algorithm identifier
 * @param input         Pointer to input data buffer
 * @param input_length  Length in bytes of the input data
 * @param salt          Pointer to salt/label buffer (may be NULL)
 * @param salt_length   Length in bytes of the salt buffer
 * @param output        Pointer to output buffer
 * @param output_size   Size in bytes of the output buffer
 * @param encrypt       true for encryption, false for decryption
 */
static void log_psa_asym_enc_params(psa_key_id_t key, psa_algorithm_t alg,
				    const uint8_t *input, size_t input_length,
				    const uint8_t *salt, size_t salt_length,
				    uint8_t *output, size_t output_size,
				    bool encrypt)
{
	LOG_INFO("=== psa_asymmetric_%s Parameters ===",
		 encrypt ? "encrypt" : "decrypt");
	LOG_INFO("  key: %u", (unsigned int)key);
	LOG_INFO("  alg: %s (0x%08x)", get_psa_asym_enc_alg_name(alg),
		 (unsigned int)alg);
	LOG_INFO("  input: %p", (const void *)input);
	LOG_INFO("  input_length: %zu", input_length);
	LOG_INFO("  salt: %p", (const void *)salt);
	LOG_INFO("  salt_length: %zu", salt_length);
	LOG_INFO("  output: %p", (void *)output);
	LOG_INFO("  output_size: %zu", output_size);
	LOG_INFO("=====================================");
}

/**
 * @brief Execute an asymmetric encrypt or decrypt operation using the PSA API
 *
 * Maps the CLI algorithm to a PSA algorithm identifier, reads the input file,
 * parses optional salt, allocates the output buffer, and calls the PSA
 * one-shot asymmetric encrypt or decrypt API.
 *
 * @param args     Parsed command-line options
 * @param encrypt  true for encryption, false for decryption
 */
static enum cli_exit_code cli_asym_enc_execute(struct parsed_options *args,
					       bool encrypt)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	unsigned char *salt = NULL;
	size_t input_size = 0;
	size_t output_size = 0;
	size_t output_length = 0;
	size_t salt_len = 0;
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

	LOG_INFO("Asymmetric %s operation started (PSA API)", direction_str);
	LOG_VERBOSE("  algo           : %d", args->op.asym_enc.algo);
	LOG_VERBOSE("  key_id         : 0x%08x (%u)", args->key_id,
		    args->key_id);
	LOG_VERBOSE("  salt_hex       : %s",
		    args->op.asym_enc.salt_hex ? args->op.asym_enc.salt_hex :
						 "(none)");
	LOG_VERBOSE("  input_filename : %s", args->input_filename);
	LOG_VERBOSE("  output_filename: %s",
		    args->output_filename ? args->output_filename : "(stdout)");

	/* Map CLI algorithm to PSA algorithm */
	LOG_VERBOSE("Mapping CLI algorithm to PSA algorithm: %d",
		    args->op.asym_enc.algo);
	alg = get_psa_asym_enc_alg(args->op.asym_enc.algo);
	if (alg == PSA_ALG_NONE) {
		LOG_ERROR("Unsupported asymmetric algorithm: %d",
			  args->op.asym_enc.algo);
		goto cleanup;
	}

	LOG_VERBOSE("PSA algorithm resolved: %s (0x%08x)",
		    get_psa_asym_enc_alg_name(alg), (unsigned int)alg);

	key = (psa_key_id_t)args->key_id;

	/* Parse salt if provided (optional for OAEP) */
	if (args->op.asym_enc.salt_hex) {
		if (util_hex_string_to_bytes(args->op.asym_enc.salt_hex, &salt,
					     &salt_len)) {
			LOG_ERROR("Failed to parse salt hex string");
			goto cleanup;
		}
	}

	/* Read input file */
	LOG_VERBOSE("Reading input file: %s", args->input_filename);
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	LOG_VERBOSE("Input file read successfully: %zu bytes", input_size);

	/*
	 * Use PSA macros for output buffer sizing.
	 * PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE covers all supported
	 * RSA key sizes.
	 */
	if (encrypt)
		output_size = PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE;
	else
		output_size = PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE;

	LOG_VERBOSE("Allocating output buffer: %zu bytes", output_size);
	output = util_alloc_buffer(output_size, "asymm enc output");
	if (!output)
		goto cleanup;

	log_psa_asym_enc_params(key, alg, input, input_size, salt, salt_len,
				output, output_size, encrypt);

	/* Call PSA asymmetric API */
	if (encrypt) {
		api_name = "psa_asymmetric_encrypt";
		LOG_VERBOSE("Calling psa_asymmetric_encrypt()");
		status = psa_asymmetric_encrypt(key, alg, input, input_size,
						salt, salt_len, output,
						output_size, &output_length);
	} else {
		api_name = "psa_asymmetric_decrypt";
		LOG_VERBOSE("Calling psa_asymmetric_decrypt()");
		status = psa_asymmetric_decrypt(key, alg, input, input_size,
						salt, salt_len, output,
						output_size, &output_length);
	}

	if (!is_psa_api_success(api_name, status)) {
		if (status == PSA_ERROR_BUFFER_TOO_SMALL)
			LOG_ERROR("Output buffer too small");
		goto cleanup;
	}

	SUCCESS("Asymmetric Encryption");

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

	if (salt)
		free(salt);

	return ret;
}

/**
 * @brief Execute asymmetric encryption using the PSA API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_asym_encrypt(struct parsed_options *args)
{
	return cli_asym_enc_execute(args, true);
}

/**
 * @brief Execute asymmetric decryption using the PSA API
 *
 * @param args  Parsed command-line options
 */
enum cli_exit_code cli_asym_decrypt(struct parsed_options *args)
{
	return cli_asym_enc_execute(args, false);
}
