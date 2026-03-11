// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include "compiler.h"
#include "helper.h"
#include "logger.h"
#include "operations.h"

/**
 * @brief Weak default implementation for RNG operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/rng.c or psa/rng.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_rng_operation(struct parsed_options *args)
{
	(void)args;
	LOG_ERROR("RNG operation not implemented in this build");
	FPRINTF(stderr, "Error: RNG operation not implemented in this build\n");
	FPRINTF(stderr, "This binary was compiled without RNG support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for RNG operation
 */
__weak void cli_rng_help(void)
{
	printf("RNG operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for RNG
 */
__weak const char *cli_rng_inline_desc(void)
{
	return "Generate random numbers (not implemented)";
}
