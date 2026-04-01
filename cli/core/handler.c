// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "operations.h"
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
 * @param operation_name: Name of the operation to find (e.g., "rng", "hash")
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
 * @param operation: Name of the operation to execute (e.g., "rng", "keygen")
 * @param parsed_args: Pointer to parsed command-line arguments
 */

static enum cli_exit_code handler_dispatch(const char *operation,
					   struct parsed_options *parsed_args)
{
	const struct operation_entry *entry = NULL;

	if (!operation) {
		FPRINTF(stderr, "Error: No operation specified\n");
		return CLI_EXIT_OPERATION_FAILURE;
	}

	entry = find_operation(operation);
	if (!entry) {
		FPRINTF(stderr, "Error: Unknown operation '%s'\n", operation);
		return CLI_EXIT_OPERATION_FAILURE;
	}

	/* Found the operation, execute it */
	return entry->opt_func(parsed_args);
}

/**
 * @brief Display help information
 *
 * @param operation: Name of operation for specific help, or NULL for general help
 * @param prog_name: Program name to display in usage message
 */

static void handler_show_help(const char *operation, const char *prog_name)
{
	const struct operation_entry *entry = NULL;

	if (!operation) {
		/* Show general help - list all operations */
		print_tool_banner();

		printf("Usage: %s <operation> [OPTIONS]\n\n", prog_name);
		printf("Available operations:\n");
		for (entry = operation_table; entry->operation_name; entry++) {
			printf("  %-15s - %s\n", entry->operation_name,
			       entry->inline_desc_func());
		}
		printf("\nUse '%s <operation> --help' for information on a specific operation.\n",
		       prog_name);
		return;
	}

	/* Show help for specific operation */
	entry = find_operation(operation);
	if (!entry) {
		FPRINTF(stderr, "Error: Unknown operation '%s'\n", operation);
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
 * @param argc: Argument count
 * @param argv: Argument vector
 *
 * Process flow:
 * 1. Store program name for help functions
 * 2. Check for minimum arguments (operation required)
 * 3. Handle global help flag (--help without operation)
 * 4. Parse command-line options
 * 5. Handle operation-specific help flag
 * 6. Initialize logger subsystem
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
		print_tool_banner();
		FPRINTF(stderr, "Usage: %s <operation> [OPTIONS]\n", prog_name);
		FPRINTF(stderr, "Try '%s --help' for more information.\n\n",
			prog_name);
		return EXIT_FAILURE;
	}

	/* Check for version flag */
	if (argc >= 2 && (!strcmp(argv[1], "--version"))) {
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

	/* Initialize logger */
	logger_init(parsed_opts.log_dest,
		    (parsed_opts.log_filename &&
		     strlen(parsed_opts.log_filename) > 0) ?
			    parsed_opts.log_filename :
			    NULL);

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
