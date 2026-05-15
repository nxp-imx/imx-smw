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
 * @brief Weak default implementation for key export operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/key_export.c or psa/key_export.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_key_export_operation(struct parsed_options *args)
{
	(void)args;
	FPRINTF(stderr,
		"Error: Key export operation not implemented in this build\n");
	FPRINTF(stderr,
		"This binary was compiled without key export support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for key export operation
 */
__weak void cli_key_export_help(void)
{
	printf("Key export operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for key export
 */
__weak const char *cli_key_export_inline_desc(void)
{
	return "Export a key from the secure subsystem (not implemented)";
}
