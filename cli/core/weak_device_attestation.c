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
 * @brief Weak default implementation for dev-get-attestation operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/device_attestation.c if it is linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code
cli_device_attestation_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("dev-get-attestation operation is only available for SMW backend (nxp_smw)");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for dev-get-attestation operation
 */
__weak void cli_device_attestation_help(void)
{
	printf("dev-get-attestation operation is not available in this build.\n");
	printf("This operation is only supported with SMW backend (nxp_smw).\n");
}

/**
 * @brief Weak default inline description for dev-get-attestation
 */
__weak const char *cli_device_attestation_inline_desc(void)
{
	return "Get device attestation certificate (not implemented)";
}
