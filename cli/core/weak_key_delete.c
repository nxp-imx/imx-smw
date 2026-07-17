// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "compiler.h"
#include "helper.h"

/**
 * @brief Weak default implementation for key delete operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/key_delete.c or psa/key_delete.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_key_delete_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("key-delete operation is not supported by this backend\n");
	return CLI_EXIT_OPERATION_FAILURE;
}

/**
 * @brief Weak default key delete help (backend-agnostic)
 */
__weak void cli_key_delete_help(void)
{
	printf("key-delete operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for key delete
 */
__weak const char *cli_key_delete_inline_desc(void)
{
	return "Delete a key from the secure subsystem (not implemented)";
}
