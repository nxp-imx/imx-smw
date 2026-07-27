// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "hash_table_generated.h"
#include "helper.h"
#include "logger.h"
#include "parser_hash.h"
#include "utils.h"

/**
 * @brief Log PSA hash operation parameters
 *
 * @param alg         PSA algorithm identifier
 * @param input       Buffer containing the message to hash
 * @param input_length Size of the input buffer in bytes
 * @param hash        Buffer where the hash is to be written
 * @param hash_size   Size of the hash buffer in bytes
 * @param hash_length Pointer where hash length will be written
 */
static void log_psa_hash_params(psa_algorithm_t alg, const uint8_t *input,
				size_t input_length, uint8_t *hash,
				size_t hash_size, size_t *hash_length)
{
	const char *alg_str = psa_hash_algo_to_string(alg);

	LOG_INFO("=== psa_hash_compute Parameters ===");
	LOG_INFO("  alg         : %s (0x%08x)", alg_str, (unsigned int)alg);
	LOG_INFO("  input       : %p", (const void *)input);
	LOG_INFO("  input_length: %zu", input_length);
	LOG_INFO("  hash        : %p", (void *)hash);
	LOG_INFO("  hash_size   : %zu", hash_size);
	LOG_INFO("  hash_length : %p", (void *)hash_length);
	LOG_INFO("====================================");
}

/**
 * @brief Display help information for hash operation
 */
void cli_hash_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Hash Operation - PSA API\n\n");

	/* Print common options */
	cli_hash_help_common();

	printf("\nExamples:\n");
	printf("  %s hash -a SHA256 -i input.bin\n", prog_name);
	printf("  %s hash -a SHAKE256 -i data.bin -l 64 -o hash.bin\n",
	       prog_name);
	printf("\n");
}

/**
 * @brief Execute hash operation using PSA API
 *
 * Computes a hash/digest of the input data using psa_hash_compute() and
 * writes the output to the specified file or stdout in the requested format.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_hash_operation(struct parsed_options *args)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	size_t input_size = 0;
	size_t output_size = 0;
	size_t output_length = 0;
	psa_algorithm_t alg = PSA_ALG_NONE;
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	FILE *fp = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	if (!args->input_filename) {
		LOG_ERROR("Missing input filename");
		goto cleanup;
	}

	LOG_INFO("Hash operation started (PSA API)");
	LOG_VERBOSE("  algo          : %d", args->op.hash.algo);
	LOG_VERBOSE("  input_file    : %s", args->input_filename);
	LOG_VERBOSE("  output_file   : %s",
		    args->output_filename ? args->output_filename : "(stdout)");
	LOG_VERBOSE("  output_length : %zu", args->op.hash.output_length);
	LOG_VERBOSE("  text_format   : %s", args->text_format ? "yes" : "no");

	/* Read input file using shared utility */
	if (util_read_file(args->input_filename, &input, &input_size))
		goto cleanup;

	/* Determine output size */
	if (args->op.hash.output_length > 0) {
		output_size = args->op.hash.output_length;
		LOG_VERBOSE("Using custom output length: %zu bytes",
			    output_size);
	} else {
		output_size = get_hash_output_length(args->op.hash.algo);
		LOG_VERBOSE("Using default output length: %zu bytes",
			    output_size);
	}

	/* Allocate output buffer */
	output = util_alloc_buffer(output_size, "hash output");
	if (!output)
		goto cleanup;

	LOG_VERBOSE("Output buffer allocated: %p (%zu bytes)", (void *)output,
		    output_size);

	/* Convert CLI algo to PSA algo */
	alg = cli_hash_algo_to_psa(args->op.hash.algo);
	LOG_VERBOSE("PSA algorithm identifier: 0x%08x", (unsigned int)alg);

	/* Log PSA API parameters */
	log_psa_hash_params(alg, input, input_size, output, output_size,
			    &output_length);

	/* Call PSA hash API */
	LOG_VERBOSE("Calling psa_hash_compute()");
	status = psa_hash_compute(alg, input, input_size, output, output_size,
				  &output_length);

	if (!is_psa_api_success("psa_hash_compute", status))
		goto cleanup;

	SUCCESS("Hash");
	LOG_VERBOSE("Hash computed: %zu bytes written", output_length);

	/* Write output */
	if (util_write_output_data(output, output_length, args->output_filename,
				   args->text_format)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (fp)
		FCLOSE(fp);

	if (input) {
		LOG_VERBOSE("Freeing input buffer");
		free(input);
	}

	if (output) {
		LOG_VERBOSE("Freeing output buffer");
		free(output);
	}

	return ret;
}
