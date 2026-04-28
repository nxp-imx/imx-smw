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
 * @brief Weak default implementation for asymmetric key generation operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/keygen_asym.c or psa/keygen_asym.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_keygen_asym_operation(struct parsed_options *args)
{
	(void)args;
	FPRINTF(stderr,
		"Error: Asymmetric key generation operation not implemented in this build\n");
	FPRINTF(stderr,
		"This binary was compiled without asymmetric key generation support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for asymmetric key generation operation
 */
__weak void cli_keygen_asym_help(void)
{
	printf("Asymmetric key generation operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for asymmetric key generation
 */
__weak const char *cli_keygen_asym_inline_desc(void)
{
	return "Generate asymmetric cryptographic key pair (not implemented)";
}
