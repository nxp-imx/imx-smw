// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include "apis_dispatcher.h"
#include "compiler.h"
#include "helper.h"
#include "parser_key_delete.h"

/**
 * @brief Weak default key delete help (backend-agnostic)
 */
__weak void cli_key_delete_help(void)
{
	printf("\n");
	print_tool_banner();
	printf("Key Delete Operation\n\n");
	cli_key_delete_help_common();
	printf("\n");
}

/**
 * @brief Weak default key delete operation (not supported)
 */
__weak enum cli_exit_code cli_key_delete_operation(struct parsed_options *args)
{
	(void)args;
	FPRINTF(stderr,
		"Error: key-delete operation is not supported by this backend\n");
	return CLI_EXIT_OPERATION_FAILURE;
}

/**
 * @brief Weak default inline description for key delete
 */
__weak const char *cli_key_delete_inline_desc(void)
{
	return "Delete a key from the secure subsystem";
}
