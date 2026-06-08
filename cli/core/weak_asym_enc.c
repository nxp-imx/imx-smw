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
 * @brief Weak default implementation for asymmetric encrypt operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/asym_enc.c or psa/asym_enc.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code
cli_asym_encrypt_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("asymmetric encrypt operation is not implemented in this build");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default implementation for asymmetric decrypt operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/asym_enc.c or psa/asym_enc.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code
cli_asym_decrypt_operation(struct parsed_options *args)
{
	(void)args;
	ERROR("asymmetric decrypt operation is not implemented in this build\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for asymmetric encrypt operation
 */
__weak void cli_asym_encrypt_help(void)
{
	printf("asymmetric encrypt operation is not available in this build.\n");
}

/**
 * @brief Weak default help for asymmetric decrypt operation
 */
__weak void cli_asym_decrypt_help(void)
{
	printf("asymmetric decrypt operation is not available in this build.\n");
}
