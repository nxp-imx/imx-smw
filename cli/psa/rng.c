// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"
#include "operations.h"
#include "utils.h"

/**
 * @brief Log PSA RNG operation parameters
 *
 * @param output: Pointer to output buffer
 * @param output_size: Size of output buffer in bytes
 */
static void log_psa_rng_params(uint8_t *output, size_t output_size)
{
	LOG_INFO("=== psa_generate_random Parameters ===");
	LOG_INFO("  output: %p", (void *)output);
	LOG_INFO("  output_size: %zu", output_size);
	LOG_INFO("======================================");
}

/**
 * @brief Display help information for RNG operation (PSA API)
 */
void cli_rng_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("RNG Operation - PSA API\n\n");

	/* Print common options */
	cli_rng_help_common();

	/* PSA-specific notes */
	printf("\nNote: PSA API does not support subsystem selection.\n\n");

	printf("Examples:\n");
	printf("  %s rng -s 32\n", prog_name);
	printf("  %s rng -s 16 -o random.bin\n", prog_name);
	printf("\n");
}

/**
 * @brief Execute RNG operation using PSA Crypto API
 *
 * Generates random data using psa_generate_random() and writes the output
 * to the specified file or stdout in the requested format.
 *
 * @param args Pointer to parsed command-line options structure
 */
enum cli_exit_code cli_rng_operation(struct parsed_options *args)
{
	unsigned char *buffer = NULL;
	psa_status_t status = PSA_SUCCESS;
	enum cli_exit_code ret = CLI_EXIT_OPERATION_FAILURE;

	if (!args) {
		LOG_ERROR("NULL arguments passed to %s", __func__);
		goto cleanup;
	}

	LOG_INFO("RNG operation (PSA API)");

	/* Validate size fits in unsigned int */
	if (args->op.rng.size > UINT32_MAX) {
		LOG_ERROR("Size %zu exceeds maximum supported value %u",
			  args->op.rng.size, UINT32_MAX);
		goto cleanup;
	}

	/* Allocate output buffer */
	buffer = util_alloc_buffer(args->op.rng.size, "RNG output");
	if (!buffer)
		goto cleanup;

	/* Log PSA API parameters */
	log_psa_rng_params(buffer, args->op.rng.size);

	/* Call PSA RNG API */
	status = psa_generate_random(buffer, args->op.rng.size);
	if (!is_psa_api_success("psa_generate_random", status))
		goto cleanup;

	/* Write output using common helper */
	if (util_write_output_data(buffer, args->op.rng.size,
				   args->output_filename, args->text_format)) {
		goto cleanup;
	}

	ret = CLI_EXIT_SUCCESS;

cleanup:
	if (buffer)
		free(buffer);

	return ret;
}
