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
 * @brief Weak default implementation for hash operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/hash.c or psa/hash.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_hash_operation(struct parsed_options *args)
{
	(void)args;
	LOG_ERROR("Hash operation not implemented in this build");
	FPRINTF(stderr,
		"Error: Hash operation not implemented in this build\n");
	FPRINTF(stderr, "This binary was compiled without Hash support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for Hash operation
 */
__weak void cli_hash_help(void)
{
	printf("Hash operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for Hash
 */
__weak const char *cli_hash_inline_desc(void)
{
	return "Compute cryptographic hash (not implemented)";
}
