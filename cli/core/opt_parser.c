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
#include "cli_print.h"
#include "helper.h"
#include "opt_parser.h"
#include "parser_encrypt.h"
#include "parser_device_attestation.h"
#include "parser_device_get_lifecycle.h"
#include "parser_device_set_lifecycle.h"
#include "parser_device_uuid.h"
#include "parser_hash.h"
#include "parser_key_export.h"
#include "parser_key_delete.h"
#include "parser_keygen_sym.h"
#include "parser_keygen_asym.h"
#include "parser_mac.h"
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
	printf("\n=================\n");
	printf("Logging Mechanism\n");
	printf("=================\n\n");

	printf("CLI supports dual logging: automatic (via environment)");
	printf(" and manual (via --v/--vv).\n\n");

	printf("1. AUTOMATIC LOGGING (Environment Variable)\n");
	printf("   export SMW_LOG_FILE=smw_cli.log	# Enable to file\n");
	printf("   export SMW_LOG_FILE=none		# Disable\n");
	printf("   unset SMW_LOG_FILE			# Use default\n\n");

	printf("2. MANUAL LOGGING (CLI Option)\n\n");
	printf("   %-35s %s\n", "Option", "Level / Destination");
	printf("   %-35s %s\n", "------", "-------------------");
	printf("   %-35s %s\n", "--v",
	       "INFO: operations and results  -> stderr");
	printf("   %-35s %s\n", "--v <filename>",
	       "INFO: operations and results  -> file");
	printf("   %-35s %s\n", "--vv",
	       "VERBOSE: API calls and params -> stderr");
	printf("   %-35s %s\n", "--vv <filename>",
	       "VERBOSE: API calls and params -> file");
	printf("\n");

	printf("Examples:\n");
	printf("  %s rng -s 32 -o random.bin --v\n", prog_name);
	printf("  %s hash -a SHA256 -i data.bin -o hash.txt --v trace.log\n",
	       prog_name);
	printf("  %s keygen-sym -t AES -s 256 -a CBC -u encrypt,decrypt",
	       prog_name);
	printf(" --transient --vv trace.log\n");
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
	  .op = OP_DEV_GET_UUID,
	  .parse_func = parse_device_uuid_options,
	  .special_func = NULL },
	{ .name = "dev-get-lifecycle",
	  .op = OP_DEV_GET_LIFECYCLE,
	  .parse_func = parse_dev_get_lifecycle_options,
	  .special_func = NULL },
	{ .name = "dev-set-lifecycle",
	  .op = OP_DEV_SET_LIFECYCLE,
	  .parse_func = parse_dev_set_lifecycle_options,
	  .special_func = NULL },
	{ .name = "dev-get-attestation",
	  .op = OP_DEV_GET_ATTESTATION,
	  .parse_func = parse_device_attestation_options,
	  .special_func = NULL },
	{ .name = "keygen-sym",
	  .op = OP_KEYGEN_SYM,
	  .parse_func = parse_keygen_sym_options,
	  .special_func = NULL },
	{ .name = "keygen-asym",
	  .op = OP_KEYGEN_ASYM,
	  .parse_func = parse_keygen_asym_options,
	  .special_func = NULL },
	{ .name = "key-export",
	  .op = OP_KEY_EXPORT,
	  .parse_func = parse_key_export_options,
	  .special_func = NULL },
	{ .name = "key-delete",
	  .op = OP_KEY_DELETE,
	  .parse_func = parse_key_delete_options,
	  .special_func = NULL },
	{ .name = "mac",
	  .op = OP_MAC,
	  .parse_func = parse_mac_options,
	  .special_func = NULL },
	{ .name = "mac-verify",
	  .op = OP_MAC_VERIFY,
	  .parse_func = parse_mac_verify_options,
	  .special_func = NULL },
	{ .name = "encrypt",
	  .op = OP_ENCRYPT,
	  .parse_func = parse_encrypt_options,
	  .special_func = NULL },
	{ .name = "decrypt",
	  .op = OP_DECRYPT,
	  .parse_func = parse_decrypt_options,
	  .special_func = NULL },
	/* Add more operations here */
	{ NULL, OP_NONE, NULL, NULL } /* Sentinel */
};

/**
 * @brief Parse subsystem option
 *
 * @param subsystem_str String representing the subsystem name
 */
smw_subsystem_t parse_subsystem(const char *subsystem_str)
{
	if (!strcasecmp(subsystem_str, "ELE"))
		return SMW_SUBSYSTEM_NAME_ELE;

	if (!strcasecmp(subsystem_str, "TEE"))
		return SMW_SUBSYSTEM_NAME_TEE;

	if (!strcasecmp(subsystem_str, "SECO"))
		return SMW_SUBSYSTEM_NAME_SECO;

	WARNING("Unknown subsystem '%s', using default\n", subsystem_str);
	return SMW_SUBSYSTEM_NAME_NONE;
}

/**
 * @brief Parse and allocate filename dynamically
 *
 * @param src        Source filename string
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
		ERROR("%s cannot start with '-'", field_name);
		goto cleanup;
	}

	dest = calloc(src_len + 1, 1);
	if (!dest) {
		ERROR("Out of memory allocating %s", field_name);
		goto cleanup;
	}

	ret = snprintf(dest, src_len + 1, "%s", src);
	if (ret < 0) {
		ERROR("Failed to set %s", field_name);
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
 * @brief Parse the --v/--vv log option (common to all operations)
 *
 * Sets the log level and destination based on the option used:
 *   --v  [dest] -> INFO level
 *   --vv [dest] -> VERBOSE level
 *
 * If no argument is given, logs to stderr.
 * If a filename argument is given, logs to that file.
 *
 * @param opts      Pointer to parsed_options structure to populate
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param prog_name The program name (executable)
 * @param operation The operation name (e.g., "rng", "hash")
 * @param level     Log level to activate (LOG_LEVEL_INFO or LOG_LEVEL_VERBOSE)
 */
int parse_log_option(struct parsed_options *opts, int argc, char **argv,
		     const char *prog_name, const char *operation,
		     enum log_level level)
{
	opts->log_level = level;
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
 * @brief Print common logging options help lines
 *
 * @param prog_name The program name (executable)
 */
void print_log_options_help(const char *prog_name)
{
	printf("      --v [dest]            Enable INFO logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("      --vv [dest]            Enable VERBOSE logging");
	printf(" (%s log --help for info)\n", prog_name);
}

/**
 * @brief Print common help option help line
 */
void print_help_option_help(void)
{
	printf("  -h, --help                Show help\n");
}

/**
 * @brief Parse command line interface options and arguments
 *
 * @param[in]  argc Number of command line arguments
 * @param[in]  argv Array of command line argument strings
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
	opts->log_level = LOG_LEVEL_INFO; /* default: INFO */

	/* Check if there is at least one argument for the operation */
	if (argc < 2) {
		ERROR("Must specify an operation");
		print_short_usage(argv[0]);
		return OP_NONE;
	}

	/* Find operation in dispatch table */
	parser = find_operation_parser(argv[1]);
	if (!parser) {
		ERROR("Invalid operation '%s'", argv[1]);
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

	/* Free operation-specific union members (mutually exclusive) */
	if (opts->operation == OP_DEV_GET_ATTESTATION) {
		if (opts->op.dev_att.challenge_filename) {
			free(opts->op.dev_att.challenge_filename);
			opts->op.dev_att.challenge_filename = NULL;
		}
	}

	if (opts->operation == OP_KEY_EXPORT) {
		if (opts->op.key_export.key_file) {
			free(opts->op.key_export.key_file);
			opts->op.key_export.key_file = NULL;
		}
	}

	if (opts->operation == OP_MAC || opts->operation == OP_MAC_VERIFY) {
		if (opts->op.mac.algo) {
			free(opts->op.mac.algo);
			opts->op.mac.algo = NULL;
		}
		if (opts->op.mac.mac_filename) {
			free(opts->op.mac.mac_filename);
			opts->op.mac.mac_filename = NULL;
		}
	}

	if (opts->operation == OP_KEY_EXPORT) {
		free(opts->op.key_export.key_file);
		opts->op.key_export.key_file = NULL;
	} else if (opts->operation == OP_KEYGEN_SYM ||
		   opts->operation == OP_KEYGEN_ASYM) {
		free(opts->op.keygen.key_type);
		opts->op.keygen.key_type = NULL;
		free(opts->op.keygen.permitted_algo);
		opts->op.keygen.permitted_algo = NULL;
		free(opts->op.keygen.usage);
		opts->op.keygen.usage = NULL;
	} else if (opts->operation == OP_ENCRYPT ||
		   opts->operation == OP_DECRYPT) {
		if (opts->cipher_family == CIPHER_FAMILY_SYMMETRIC) {
			free(opts->op.cipher.iv_hex);
			opts->op.cipher.iv_hex = NULL;
		} else if (opts->cipher_family == CIPHER_FAMILY_ASYMMETRIC) {
			free(opts->op.asym_enc.salt_hex);
			opts->op.asym_enc.salt_hex = NULL;
		}
	}
}
