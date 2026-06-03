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
 * @brief Weak default implementation for encrypt operation
 *
 * This function is used when the backend (SMW/PSA) doesn't provide
 * an implementation. It will be overridden by the strong symbol in
 * smw/cipher.c or psa/cipher.c if they are linked.
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_encrypt_operation(struct parsed_options *args)
{
	(void)args;
	FPRINTF(stderr,
		"Error: Encrypt operation not implemented in this build\n");
	FPRINTF(stderr, "This binary was compiled without cipher support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default implementation for decrypt operation
 *
 * @param args Pointer to parsed command-line options structure
 */
__weak enum cli_exit_code cli_decrypt_operation(struct parsed_options *args)
{
	(void)args;
	FPRINTF(stderr,
		"Error: Decrypt operation not implemented in this build\n");
	FPRINTF(stderr, "This binary was compiled without cipher support.\n");
	return CLI_EXIT_NOT_IMPLEMENTED;
}

/**
 * @brief Weak default help for encrypt operation
 */
__weak void cli_encrypt_help(void)
{
	printf("Encrypt operation is not available in this build.\n");
}

/**
 * @brief Weak default help for decrypt operation
 */
__weak void cli_decrypt_help(void)
{
	printf("Decrypt operation is not available in this build.\n");
}
