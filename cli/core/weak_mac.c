// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "compiler.h"
#include "helper.h"
#include "logger.h"

/**
 * @brief Weak default implementation for mac operation
 *
 * These functions are used when the backend (SMW/PSA) doesn't provide
 * an implementation. they will be overridden by the strong symbol in
 * smw/mac.c or psa/mac.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_mac_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("mac operation not implemented in this build");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

__weak enum cli_exit_code cli_mac_verify_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("mac-verify operation not implemented in this build");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for MAC operation
 */
__weak void cli_mac_help(void)
{
	printf("mac operation is not available in this build.\n");
}

/**
 * @brief Weak default inline description for MAC
 */
__weak const char *cli_mac_inline_desc(void)
{
	return "Compute cryptographic MAC (not implemented)";
}
