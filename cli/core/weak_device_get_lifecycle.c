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
 * @brief Weak default implementation for dev-get-lifecycle operation
 */
__weak enum cli_exit_code
cli_dev_get_lifecycle_operation(struct parsed_options *args)
{
	(void)args;
	LOG_ERROR("Get dev lifecycle operation not implemented in this build.");
	FPRINTF(stderr,
		"This operation is only available for SMW backend (nxp_smw).\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for dev-get-lifecycle operation
 */
__weak void cli_dev_get_lifecycle_help(void)
{
	printf("Get dev lifecycle operation is not available in this build.\n");
	printf("This operation is only supported with SMW backend (nxp_smw).\n");
}

/**
 * @brief Weak default inline description for dev-get-lifecycle
 */
__weak const char *cli_dev_get_lifecycle_inline_desc(void)
{
	return "Get device lifecycle (not implemented)";
}
