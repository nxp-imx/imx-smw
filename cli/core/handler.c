// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "parser_encrypt.h"
#include "parser_device_attestation.h"
#include "parser_device_get_lifecycle.h"
#include "parser_device_set_lifecycle.h"
#include "parser_device_uuid.h"
#include "parser_hash.h"
#include "parser_key_export.h"
#include "parser_key_delete.h"
#include "parser_keygen_asym.h"
#include "parser_keygen_sym.h"
#include "parser_mac.h"
#include "parser_rng.h"
#include "utils.h"

/* Operation dispatch table entry */
struct operation_entry {
	const char *operation_name;
	enum cli_exit_code (*opt_func)(struct parsed_options *args);
	void (*help_func)(void);
	const char *(*inline_desc_func)(void);
};

/* Program Name (accessible to help functions) */
static void print_version(const char *prog_name)
{
	printf("%s version %s", prog_name, CLI_VERSION);
	printf(" using libsmw.so version %s\n", SMW_LIB_VERSION);
}

/**
 * @brief Dispatch encrypt to symmetric or asymmetric based on cipher_family
 */
static enum cli_exit_code cli_encrypt_dispatch(struct parsed_options *args)
{
	if (args->cipher_family == CIPHER_FAMILY_ASYMMETRIC)
		return cli_asym_encrypt(args);

	return cli_encrypt_operation(args);
}

/**
 * @brief Dispatch decrypt to symmetric or asymmetric based on cipher_family
 */
static enum cli_exit_code cli_decrypt_dispatch(struct parsed_options *args)
{
	if (args->cipher_family == CIPHER_FAMILY_ASYMMETRIC)
		return cli_asym_decrypt(args);

	return cli_decrypt_operation(args);
}

/* ============================================================================
 * DISPATCH TABLE
 * ============================================================================
 */
static const struct operation_entry operation_table[] = {
	{ .operation_name = "rng",
	  .opt_func = cli_rng_operation,
	  .help_func = cli_rng_help,
	  .inline_desc_func = cli_rng_inline_desc },
	{ .operation_name = "hash",
	  .opt_func = cli_hash_operation,
	  .help_func = cli_hash_help,
	  .inline_desc_func = cli_hash_inline_desc },
	{ .operation_name = "dev-get-uuid",
	  .opt_func = cli_device_uuid_operation,
	  .help_func = cli_device_uuid_help,
	  .inline_desc_func = cli_device_uuid_inline_desc },
	{ .operation_name = "dev-get-lifecycle",
	  .opt_func = cli_dev_get_lifecycle_operation,
	  .help_func = cli_dev_get_lifecycle_help,
	  .inline_desc_func = cli_dev_get_lifecycle_inline_desc },
	{ .operation_name = "dev-set-lifecycle",
	  .opt_func = cli_dev_set_lifecycle_operation,
	  .help_func = cli_dev_set_lifecycle_help,
	  .inline_desc_func = cli_dev_set_lifecycle_inline_desc },
	{ .operation_name = "dev-get-attestation",
	  .opt_func = cli_device_attestation_operation,
	  .help_func = cli_device_attestation_help,
	  .inline_desc_func = cli_device_attestation_inline_desc },
	{ .operation_name = "keygen-sym",
	  .opt_func = cli_keygen_sym_operation,
	  .help_func = cli_keygen_sym_help,
	  .inline_desc_func = cli_keygen_sym_inline_desc },
	{ .operation_name = "keygen-asym",
	  .opt_func = cli_keygen_asym_operation,
	  .help_func = cli_keygen_asym_help,
	  .inline_desc_func = cli_keygen_asym_inline_desc },
	{ .operation_name = "key-export",
	  .opt_func = cli_key_export_operation,
	  .help_func = cli_key_export_help,
	  .inline_desc_func = cli_key_export_inline_desc },
	{ .operation_name = "key-delete",
	  .opt_func = cli_key_delete_operation,
	  .help_func = cli_key_delete_help,
	  .inline_desc_func = cli_key_delete_inline_desc },
	{ .operation_name = "mac",
	  .opt_func = cli_mac_operation,
	  .help_func = cli_mac_help,
	  .inline_desc_func = cli_mac_inline_desc },
	{ .operation_name = "mac-verify",
	  .opt_func = cli_mac_verify_operation,
	  .help_func = cli_mac_verify_help,
	  .inline_desc_func = cli_mac_verify_inline_desc },
	{ .operation_name = "encrypt",
	  .opt_func = cli_encrypt_dispatch,
	  .help_func = cli_encrypt_help,
	  .inline_desc_func = cli_encrypt_inline_desc },
	{ .operation_name = "decrypt",
	  .opt_func = cli_decrypt_dispatch,
	  .help_func = cli_decrypt_help,
	  .inline_desc_func = cli_decrypt_inline_desc },
	/* Add more operations here as we implement them */
	{ NULL, NULL, NULL, NULL } /* Sentinel */
};

/* ============================================================================
 * HELPER FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Find operation entry in the dispatch table
 *
 * @param operation_name Name of the operation to find
 */
static const struct operation_entry *find_operation(const char *operation_name)
{
	const struct operation_entry *entry = NULL;

	if (!operation_name)
		return NULL;

	for (entry = operation_table; entry->operation_name; entry++) {
		if (!strcmp(entry->operation_name, operation_name))
			return entry;
	}

	return NULL;
}

/* ============================================================================
 * HANDLER FUNCTIONS
 * ============================================================================
 */

/**
 * @brief Dispatch operation to appropriate handler
 *
 * @param operation   Name of the operation to execute
 * @param parsed_args Pointer to parsed command-line arguments
 */
static enum cli_exit_code handler_dispatch(const char *operation,
					   struct parsed_options *parsed_args)
{
	const struct operation_entry *entry = NULL;

	if (!operation) {
		ERROR("No operation specified\n");
		return CLI_EXIT_OPERATION_FAILURE;
	}

	entry = find_operation(operation);
	if (!entry) {
		ERROR("Unknown operation '%s'\n", operation);
		return CLI_EXIT_OPERATION_FAILURE;
	}

	return entry->opt_func(parsed_args);
}

/**
 * @brief Display help information
 *
 * @param operation Name of operation for specific help, or NULL for general
 * @param prog_name Program name to display in usage message
 */
static void handler_show_help(const char *operation, const char *prog_name)
{
	const struct operation_entry *entry = NULL;

	if (!operation) {
		print_tool_banner();

		printf("Usage: %s <operation> [OPTIONS]\n\n", prog_name);
		printf("Available operations:\n");
		for (entry = operation_table; entry->operation_name; entry++) {
			printf("  %-20s - %s\n", entry->operation_name,
			       entry->inline_desc_func());
		}
		printf("\nUse '%s <operation> --help' for information on a",
		       prog_name);
		printf(" specific operation.\n\n");
		return;
	}

	entry = find_operation(operation);
	if (!entry) {
		ERROR("Unknown operation '%s'\n", operation);
		return;
	}

	entry->help_func();
}

/* ============================================================================
 * MAIN FUNCTION
 * ============================================================================
 */

/**
 * @brief Program entry point
 *
 * @param argc Argument count
 * @param argv Argument vector
 *
 * Process flow:
 * 1. Store program name for help functions
 * 2. Check for minimum arguments (operation required)
 * 3. Handle global help/version flags
 * 4. Parse command-line options
 * 5. Handle operation-specific help flag
 * 6. Initialize logger subsystem (with log level)
 * 7. Initialize security backend (SMW or PSA)
 * 8. Dispatch to operation handler
 * 9. Cleanup and exit
 */
int main(int argc, char *argv[])
{
	struct parsed_options parsed_opts = { 0 };
	enum operation operation = OP_NONE;
	enum cli_exit_code ret = CLI_EXIT_SUCCESS;
	const char *prog_name = argv[0];

	/* Store program name for help functions */
	set_program_name(prog_name);

	if (argc < 2) {
		printf("\n");
		print_tool_banner();
		FPRINTF(stderr, "Usage: %s <operation> [OPTIONS]\n", prog_name);
		FPRINTF(stderr, "Try '%s --help' for more information.\n\n",
			prog_name);
		return EXIT_FAILURE;
	}

	/* Check for version flag */
	if (!strcmp(argv[1], "--version")) {
		print_version(prog_name);
		return EXIT_SUCCESS;
	}

	/* Check for global help */
	if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		printf("\n");
		print_version(prog_name);
		printf("\n");
		handler_show_help(NULL, prog_name);
		return EXIT_SUCCESS;
	}

	/* Parse command line options */
	operation = parse_cli_options(argc, argv, &parsed_opts);
	if (operation == OP_NONE) {
		opt_parser_cleanup(&parsed_opts);
		return EXIT_FAILURE;
	}

	/* Check for operation-specific help or list */
	if (parsed_opts.show_help) {
		handler_show_help(parsed_opts.operation_name, prog_name);
		opt_parser_cleanup(&parsed_opts);
		return EXIT_SUCCESS;
	}

	if (parsed_opts.show_list) {
		opt_parser_cleanup(&parsed_opts);
		return EXIT_SUCCESS;
	}

	/*
	 * Initialize logger with:
	 *   - destination (none / stderr / file)
	 *   - optional filename
	 *   - log level (INFO by default, VERBOSE if --verbose was passed)
	 */
	logger_init(parsed_opts.log_dest,
		    (parsed_opts.log_filename &&
		     strlen(parsed_opts.log_filename) > 0) ?
			    parsed_opts.log_filename :
			    NULL,
		    parsed_opts.log_level);

	LOG_VERBOSE("Operation: %s | Log level: %s", parsed_opts.operation_name,
		    parsed_opts.log_level == LOG_LEVEL_VERBOSE ? "VERBOSE" :
								 "INFO");

	/* Initialize backend */
	ret = cli_backend_init();
	if (ret) {
		logger_cleanup();
		opt_parser_cleanup(&parsed_opts);
		return EXIT_FAILURE;
	}

	/* Dispatch to the appropriate operation handler */
	ret = handler_dispatch(parsed_opts.operation_name, &parsed_opts);

	/* Cleanup */
	logger_cleanup();
	opt_parser_cleanup(&parsed_opts);

	return (ret == CLI_EXIT_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
