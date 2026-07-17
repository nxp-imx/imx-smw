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
 * @brief Weak default implementation for dev-get-uuid operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/device_uuid.c if it is linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_device_uuid_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("dev-get-uuid operation is only available for SMW backend (nxp_smw)");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for dev-get-uuid operation
 */
__weak void cli_device_uuid_help(void)
{
	printf("dev-get-uuid operation is not available in this build.\n");
	printf("This operation is only supported with SMW backend (nxp_smw).\n");
}

/**
 * @brief Weak default inline description for dev-get-uuid
 */
__weak const char *cli_device_uuid_inline_desc(void)
{
	return "Get device UUID (not implemented)";
}
