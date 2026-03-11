// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <smw_crypto.h>
#include <smw_status.h>
#include "common.h"
#include "helper.h"
#include "logger.h"
#include "operations.h"
#include "utils.h"

/**
 * @brief Log SMW RNG operation parameters
 *
 * @param args: Pointer to SMW RNG arguments structure
 */
static void cli_log_smw_rng_params(const struct smw_rng_args *args)
{
	if (!args) {
		LOG_ERROR("RNG args is NULL");
		return;
	}

	LOG_INFO("=== smw_rng Parameters (smw_rng_args) ===");
	LOG_INFO("  version: %u", args->version);
	LOG_INFO("  subsystem_name: %s",
		 cli_smw_get_subsystem_name(args->subsystem_name));
	LOG_INFO("  output: %p", (void *)args->output);
	LOG_INFO("  output_length: %u", args->output_length);
	LOG_INFO("=========================================");
}

/**
 * @brief Display help information for RNG operation (SMW API)
 */
void cli_rng_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("RNG Operation - SMW API\n\n");

	/* Print common options */
	cli_rng_help_common();

	/* SMW-specific options */
	printf("  -S, --subsystem <name>  Force subsystem (ELE/TEE/SECO)\n\n");
	printf("Examples:\n");
	printf("  %s rng -s 32\n", prog_name);
	printf("  %s rng -s 16 -o random.bin -S TEE\n", prog_name);
	printf("\n");
}

/**
 * @brief Execute RNG operation using SMW API
 *
 * Generates random data using smw_rng() and writes the output
 * to the specified file or stdout in the requested format.
 *
 * @param args Pointer to parsed command-line options structure
 */
enum cli_exit_code cli_rng_operation(struct parsed_options *args)
{
	unsigned char *buffer = NULL;
	struct smw_rng_args rng_args = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE; // Assume failure

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("RNG operation (SMW API)");

	/* Validate size fits in unsigned int */
	if (args->size > UINT32_MAX) {
		LOG_ERROR("Size %zu exceeds maximum supported value %u",
			  args->size, UINT32_MAX);
		goto cleanup;
	}

	/* Allocate output buffer */
	buffer = cli_alloc_buffer(args->size, "RNG output");
	if (!buffer)
		goto cleanup;

	/* Setup SMW RNG arguments */
	rng_args.version = 0;
	rng_args.output = buffer;
	rng_args.output_length = (unsigned int)args->size;

	if (args->subsystem != SMW_SUBSYSTEM_NAME_NONE)
		rng_args.subsystem_name = args->subsystem;

	cli_log_smw_rng_params(&rng_args);

	/* Call SMW RNG API */
	status = smw_rng(&rng_args);
	if (!is_smw_api_success("smw_rng", status))
		goto cleanup;

	/* Write output using common helper */
	if (cli_write_output_data(buffer, args->size, args->output_filename,
				  args->text_format) != 0) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (buffer)
		free(buffer);

	return ret;
}
