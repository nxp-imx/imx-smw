// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "helper.h"
#include "opt_parser.h"
#include "parser_device_attestation.h"
#include "parser_device_get_lifecycle.h"
#include "parser_device_uuid.h"
#include "parser_hash.h"
#include "parser_rng.h"

/**
 * Operation parser dispatch table entry
 */
struct operation_parser {
	const char *name;
	enum operation op;
	int (*parse_func)(int argc, char **argv, struct parsed_options *opts,
			  const char *prog_name);
	void (*special_func)(const char *prog_name);
};

/**
 * @brief Print short usage information for general errors
 *
 * @param prog_name The name of the program executable
 */
static void print_short_usage(const char *prog_name)
{
	FPRINTF(stderr, "\nTry '%s --help' for more information.\n\n",
		prog_name);
}

/**
 * @brief Print detailed logging help
 *
 * @param prog_name The name of the program executable
 */
static void print_logging_help(const char *prog_name)
{
	printf("\n===================\n");
	printf("Logging Mechanism\n");
	printf("===================\n\n");

	printf("CLI supports dual logging: automatic (via environment) and manual (via -L).\n\n");

	printf("1. AUTOMATIC LOGGING (Environment Variable)\n");
	printf("   export SMW_LOG_FILE=smw_cli.log	# Enable to file\n");
	printf("   export SMW_LOG_FILE=none		# Disable\n");
	printf("   unset SMW_LOG_FILE			# Use default\n\n");

	printf("2. MANUAL LOGGING (CLI Option)\n");
	printf("   -L		      # Log to terminal output\n");
	printf("   -L <filename>      # Log to file\n\n");

	printf("Examples:\n");
	printf("  %s rng -s 32 -o random.bin -L\n", prog_name);
	printf("  %s hash -a SHA256 -i data.bin -o hash.txt -L trace.log\n",
	       prog_name);
	printf("\n");
}

/**
 * Operation parser dispatch table
 */
static const struct operation_parser operation_parsers[] = {
	{ .name = "rng",
	  .op = OP_RNG,
	  .parse_func = parse_rng_options,
	  .special_func = NULL },
	{ .name = "hash",
	  .op = OP_HASH,
	  .parse_func = parse_hash_options,
	  .special_func = NULL },
	{ .name = "log",
	  .op = OP_NONE,
	  .parse_func = NULL,
	  .special_func = print_logging_help },
	{ .name = "dev-get-uuid",
	  .op = OP_DEVICE_UUID,
	  .parse_func = parse_device_uuid_options,
	  .special_func = NULL },
	{ .name = "dev-get-lifecycle",
	  .op = OP_DEVICE_LIFECYCLE,
	  .parse_func = parse_dev_get_lifecycle_options,
	  .special_func = NULL },
	{ .name = "dev-get-attestation",
	  .op = OP_DEVICE_ATTESTATION,
	  .parse_func = parse_device_attestation_options,
	  .special_func = NULL },
	/* Add more operations here */
	{ NULL, OP_NONE, NULL, NULL } /* Sentinel */
};

/**
 * @brief Parse subsystem option
 *
 * @param subsystem_str String representing the subsystem name (e.g., "ELE", "TEE", "SECO")
 */
smw_subsystem_t parse_subsystem(const char *subsystem_str)
{
	if (!strcasecmp(subsystem_str, "ELE"))
		return SMW_SUBSYSTEM_NAME_ELE;

	if (!strcasecmp(subsystem_str, "TEE"))
		return SMW_SUBSYSTEM_NAME_TEE;

	if (!strcasecmp(subsystem_str, "SECO"))
		return SMW_SUBSYSTEM_NAME_SECO;

	FPRINTF(stderr, "Warning: Unknown subsystem '%s', using default\n",
		subsystem_str);
	return SMW_SUBSYSTEM_NAME_NONE;
}

/**
 * @brief Parse and allocate filename dynamically
 *
 * @param src Source filename string
 * @param field_name Field name for error messages
 */
char *parse_file_opt(const char *src, const char *field_name)
{
	int ret = -1;
	char *dest = NULL;
	size_t src_len = 0;

	if (!src || !field_name)
		goto cleanup;

	src_len = strlen(src);
	if (!src_len)
		goto cleanup;

	if (src[0] == '-') {
		FPRINTF(stderr, "Error: %s cannot start with '-'.\n",
			field_name);
		goto cleanup;
	}

	dest = calloc(src_len + 1, 1);
	if (!dest) {
		FPRINTF(stderr, "Error: Out of memory allocating %s\n",
			field_name);
		goto cleanup;
	}

	ret = snprintf(dest, src_len + 1, "%s", src);
	if (ret < 0) {
		FPRINTF(stderr, "Error: Failed to set %s\n", field_name);
		goto cleanup;
	}

	ret = 0;

cleanup:
	if (ret && dest) {
		free(dest);
		dest = NULL;
	}

	return dest;
}

/**
 * @brief Parse the -L/--log option (common to all operations)
 *
 * @param opts Pointer to parsed_options structure to populate with log settings
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param prog_name The program name (executable)
 * @param operation The operation name (e.g., "rng", "hash")
 */
int parse_log_option(struct parsed_options *opts, int argc, char **argv,
		     const char *prog_name, const char *operation)
{
	opts->log_dest = LOG_DEST_STDERR;

	if (optarg) {
		if (!strcmp(optarg, "-") || !strcasecmp(optarg, "stderr")) {
			opts->log_dest = LOG_DEST_STDERR;
		} else {
			opts->log_dest = LOG_DEST_FILE;
			opts->log_filename =
				parse_file_opt(optarg, "Log filename");
			if (!opts->log_filename) {
				print_help_hint(prog_name, operation);
				return -1;
			}
		}
	} else if (optind < argc && argv[optind][0] != '-') {
		opts->log_dest = LOG_DEST_FILE;
		opts->log_filename =
			parse_file_opt(argv[optind++], "Log filename");
		if (!opts->log_filename) {
			print_help_hint(prog_name, operation);
			return -1;
		}
	}

	return 0;
}

/**
 * @brief Print operation-specific help hint
 *
 * @param prog_name The program name (executable)
 * @param operation The operation name (e.g., "rng", "hash")
 */
void print_help_hint(const char *prog_name, const char *operation)
{
	FPRINTF(stderr, "\nTry '%s %s --help' for more information.\n\n",
		prog_name, operation);
}

/**
 * @brief Find operation parser in dispatch table
 *
 * @param operation_name Operation name string
 */
static const struct operation_parser *
find_operation_parser(const char *operation_name)
{
	const struct operation_parser *parser = NULL;

	if (!operation_name)
		return NULL;

	for (parser = operation_parsers; parser->name; parser++) {
		if (!strcmp(parser->name, operation_name))
			return parser;
	}

	return NULL;
}

/**
 * @brief Parse command line interface options and arguments
 *
 * @param[in] argc Number of command line arguments
 * @param[in] argv Array of command line argument strings
 * @param[out] opts Pointer to parsed_options structure to populate
 */
enum operation parse_cli_options(int argc, char **argv,
				 struct parsed_options *opts)
{
	const struct operation_parser *parser = NULL;

	/* Initialize options structure */
	memset(opts, 0, sizeof(struct parsed_options));
	opts->subsystem = SMW_SUBSYSTEM_NAME_NONE;
	opts->log_dest = LOG_DEST_NONE;

	/* Check if there is at least one argument for the operation */
	if (argc < 2) {
		FPRINTF(stderr, "Error: Must specify an operation\n");
		print_short_usage(argv[0]);
		return OP_NONE;
	}

	/* Find operation in dispatch table */
	parser = find_operation_parser(argv[1]);
	if (!parser) {
		FPRINTF(stderr, "Error: Invalid operation '%s'\n", argv[1]);
		print_short_usage(argv[0]);
		return OP_NONE;
	}

	/* Handle special operations (e.g., "log" command) */
	if (parser->special_func) {
		parser->special_func(argv[0]);
		return OP_NONE;
	}

	/* Set operation info */
	opts->operation = parser->op;
	opts->operation_name = parser->name;

	/* Reset getopt for parsing from argv[2] onwards */
	optind = 2;

	/* Parse operation-specific options */
	if (parser->parse_func) {
		if (parser->parse_func(argc, argv, opts, argv[0]))
			return OP_NONE;
	}

	return parser->op;
}

/**
 * @brief Cleanup parsed options
 *
 * @param opts Pointer to parsed_options structure to cleanup
 */
void opt_parser_cleanup(struct parsed_options *opts)
{
	if (!opts)
		return;

	/* Free dynamically allocated filenames */
	if (opts->output_filename) {
		free(opts->output_filename);
		opts->output_filename = NULL;
	}

	if (opts->input_filename) {
		free(opts->input_filename);
		opts->input_filename = NULL;
	}

	if (opts->log_filename) {
		free(opts->log_filename);
		opts->log_filename = NULL;
	}

	if (opts->operation == OP_DEVICE_ATTESTATION) {
		if (opts->op.dev_att.challenge_filename) {
			free(opts->op.dev_att.challenge_filename);
			opts->op.dev_att.challenge_filename = NULL;
		}
	}
}
