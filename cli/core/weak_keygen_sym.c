// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include "apis_dispatcher.h"
#include "compiler.h"
#include "helper.h"
#include "logger.h"

/**
 * @brief Weak default implementation for symmetric key generation operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/keygen_sym.c or psa/keygen_sym.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_keygen_sym_operation(struct parsed_options *args)
{
	(void)args;
	FPRINTF(stderr,
		"Error: Symmetric key generation operation not implemented in this build\n");
	FPRINTF(stderr,
		"This binary was compiled without symmetric key generation support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for symmetric key generation operation
 */
__weak void cli_keygen_sym_help(void)
{
	printf("Symmetric key generation operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for symmetric key generation
 */
__weak const char *cli_keygen_sym_inline_desc(void)
{
	return "Generate symmetric cryptographic key (not implemented)";
}
