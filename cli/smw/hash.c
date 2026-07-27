// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_config.h>
#include <smw_crypto.h>
#include <smw_status.h>
#include <stdio.h>
#include <stdlib.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "common.h"
#include "error_handler.h"
#include "hash_table_generated.h"
#include "helper.h"
#include "logger.h"
#include "parser_hash.h"
#include "utils.h"

/**
 * @brief Log SMW hash operation parameters
 *
 * @param args Pointer to SMW hash arguments structure
 */
static void log_smw_hash_params(const struct smw_hash_args *args)
{
	if (!args)
		return;

	LOG_INFO("=== smw_hash Parameters (smw_hash_args) ===");
	LOG_INFO("  version       : %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  algo_name     : %s",
		 cli_smw_get_hash_algo_name(args->algo_name));
	LOG_INFO("  input         : %p", (void *)args->input);
	LOG_INFO("  input_length  : %u", args->input_length);
	LOG_INFO("  output        : %p", (void *)args->output);
	LOG_INFO("  output_length : %u", args->output_length);
	LOG_INFO("===========================================");
}

/**
 * @brief Display help information for hash operation
 */
void cli_hash_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Hash Operation - SMW API\n\n");

	/* Print common options */
	cli_hash_help_common();

	/* SMW-specific options */
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Examples:\n");
	printf("  %s hash -a SHA256 -i input.bin\n", prog_name);
	printf("  %s hash -a SHAKE256 -i data.bin -l 64 -o hash.bin\n",
	       prog_name);
	printf("\n");
}

/**
 * @brief Execute hash operation using SMW API
 *
 * Computes a hash/digest of the input data using smw_hash() and writes
 * the output to the specified file or stdout in the requested format.
 *
 * @param args Pointer to parsed command-line arguments
 */
enum cli_exit_code cli_hash_operation(struct parsed_options *args)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
	size_t input_size = 0;
	size_t output_size = 0;
	struct smw_hash_args hash_args = { 0 };
	enum smw_status_code config_status = SMW_STATUS_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;
	smw_hash_algo_t smw_algo = SMW_HASH_ALGO_NAME_NONE;
	FILE *fp = NULL;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	if (!args->input_filename) {
		LOG_ERROR("Missing input filename");
		goto cleanup;
	}

	LOG_INFO("Hash operation started (SMW API)");
	LOG_VERBOSE("  algo          : %d", args->op.hash.algo);
	LOG_VERBOSE("  input_file    : %s", args->input_filename);
	LOG_VERBOSE("  output_file   : %s",
		    args->output_filename ? args->output_filename : "(stdout)");
	LOG_VERBOSE("  output_length : %zu", args->op.hash.output_length);
	LOG_VERBOSE("  text_format   : %s", args->text_format ? "yes" : "no");

	/* Convert CLI algo enum to SMW algo */
	smw_algo = cli_hash_algo_to_smw(args->op.hash.algo);
	LOG_VERBOSE("  smw_algo      : %s",
		    cli_smw_get_hash_algo_name(smw_algo));

	/* Check if the algo is supported by subsystem */
	LOG_VERBOSE("Checking algorithm support via smw_config_check_digest()");
	config_status = smw_config_check_digest(args->subsystem, smw_algo);

	if (config_status != SMW_STATUS_OK) {
		LOG_ERROR("Algorithm not supported by subsystem: %s (%d)",
			  cli_smw_status_to_name(config_status), config_status);
		goto cleanup;
	}

	LOG_VERBOSE("Algorithm supported by subsystem");

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

	/* Setup SMW hash arguments */
	hash_args.version = 0;
	hash_args.algo_name = smw_algo;
	if (!hash_args.algo_name) {
		LOG_ERROR("Failed to convert hash algorithm");
		goto cleanup;
	}
	hash_args.input = input;
	hash_args.input_length = input_size;
	hash_args.output = output;
	hash_args.output_length = output_size;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE)
		hash_args.subsystem_name = args->subsystem;

	/* Log SMW API parameters */
	log_smw_hash_params(&hash_args);

	/* Call SMW hash API */
	LOG_VERBOSE("Calling smw_hash()");
	status = smw_hash(&hash_args);
	if (!is_smw_api_success("smw_hash", status))
		goto cleanup;

	SUCCESS("Hash");

	LOG_VERBOSE("Writing output data (%zu bytes)", output_size);

	/* Write output */
	if (util_write_output_data(output, output_size, args->output_filename,
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
