// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "cli_print.h"
#include "hash_table_generated.h"
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "parser_hash.h"
#include "utils.h"

#define MAX_HASH_LENGTH 1024

/* Short getopt options for HASH */
static const char *hash_short_opts = ":ha:i:o:S:l:t";

/* Define options for HASH operation */
static const struct option hash_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "algo", required_argument, 0, 'a' },
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "text", no_argument, 0, 't' },
	{ "length", required_argument, 0, 'l' },
	{ "list", no_argument, 0, 0 },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for hash operation
 */
const char *cli_hash_inline_desc(void)
{
	return "Compute cryptographic hash";
}

/**
 * @brief Print common hash help (backend-agnostic)
 */
void cli_hash_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Usage: %s hash [OPTIONS]\n\n", prog_name);
	printf("Compute cryptographic hash/digest of input data.\n\n");

	printf("Options:\n");
	printf("\n      --list		    List all available hash algorithms\n\n");
	printf("  -a, --algo <algorithm>    Hash algorithm (required)\n");
	printf("  -i, --input <file>        Input file (required)\n");
	printf("  -o, --output <file>       Output file\n");
	printf("  -l, --length <bytes>      Output length for XOF algorithms (e.g. SHAKE256)\n");
	printf("  -t, --text                Write hex format\n");
	print_log_options_help(prog_name);
	print_help_option_help();
}

/**
 * @brief Print list of available hash algorithms
 */
static void print_hash_algo_list(void)
{
	size_t i = 0;
	const struct hash_algo_info *info = NULL;

	printf("\n");
	printf("Available Hash Algorithms\n");
	printf("=========================\n\n");
	printf("%-15s %-12s %s\n", "Algorithm", "Digest Size", "Description");
	printf("%-15s %-12s %s\n", "---------", "-----------", "-----------");

	for (; i < hash_algo_table_size; i++) {
		info = &hash_algo_table[i];

		if (info->is_xof) {
			printf("%-15s %-12s %s\n", info->name, "variable",
			       info->description);
		} else {
			printf("%-15s %-12u %s\n", info->name, info->digest_len,
			       info->description);
		}
	}
	printf("\nNote: Actual support depends on the backend and subsystem capabilities.\n");
	printf("      The operation may fail at runtime if unsupported.\n\n");
}

/**
 * @brief Parse hash algorithm string to enum
 *
 * @param algo_str String representing the hash algorithm
 */
static enum hash_algo parse_hash_algo(const char *algo_str)
{
	size_t i = 0;

	/* Validate input */
	if (!algo_str || algo_str[0] == '\0') {
		ERROR("Hash algorithm cannot be empty");
		return HASH_ALGO_NONE;
	}

	/* Reject if it looks like an option */
	if (algo_str[0] == '-') {
		ERROR("Hash algorithm cannot start with '-'");
		PRINT_USE_LIST("algorithms");
		return HASH_ALGO_NONE;
	}

	/* Search in the hash algorithm table */
	for (; i < hash_algo_table_size; i++) {
		if (!strcasecmp(algo_str, hash_algo_table[i].name))
			return hash_algo_table[i].algo;
	}

	ERROR("Unknown hash algorithm '%s'", algo_str);
	PRINT_USE_LIST("algorithms");
	return HASH_ALGO_NONE;
}

/**
 * @brief Parse command-line options for HASH operation
 *
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param opts      Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_hash_options(int argc, char **argv, struct parsed_options *opts,
		       const char *prog_name)
{
	int opt = 0;
	int opt_index = 0;
	opterr = 0;

	LOG_VERBOSE("Parsing hash options (argc=%d)", argc);

	while ((opt = getopt_long(argc, argv, hash_short_opts, hash_options,
				  &opt_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(hash_options[opt_index].name, "list")) {
				opts->show_list = true;
			} else if (!strcmp(hash_options[opt_index].name, "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "hash",
						     LOG_LEVEL_INFO))
					return -1;
			} else if (!strcmp(hash_options[opt_index].name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "hash",
						     LOG_LEVEL_VERBOSE))
					return -1;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'a':
			if (!optarg) {
				ERROR("--algo requires an argument");
				print_help_hint(prog_name, "hash");
				return -1;
			}
			opts->op.hash.algo = parse_hash_algo(optarg);
			if (opts->op.hash.algo == HASH_ALGO_NONE) {
				print_help_hint(prog_name, "hash");
				return -1;
			}
			LOG_VERBOSE("  algo = %s", optarg);
			break;

		case 'i':
			opts->input_filename =
				parse_file_opt(optarg, "Input filename");
			if (!opts->input_filename) {
				print_help_hint(prog_name, "hash");
				return -1;
			}
			LOG_VERBOSE("  input_filename = %s",
				    opts->input_filename);
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name, "hash");
				return -1;
			}
			LOG_VERBOSE("  output_filename = %s",
				    opts->output_filename);
			break;

		case 'l': {
			char *endptr = NULL;
			unsigned long tmp = 0;

			if (!optarg) {
				ERROR("--length requires an argument");
				print_help_hint(prog_name, "hash");
				return -1;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);

			if (errno || endptr == optarg || *endptr != '\0') {
				ERROR("Invalid length value '%s'", optarg);
				print_help_hint(prog_name, "hash");
				return -1;
			}

			if (!tmp || tmp > MAX_HASH_LENGTH) {
				ERROR("Length must be between 1 and 1024 bytes");
				print_help_hint(prog_name, "hash");
				return -1;
			}

			opts->op.hash.output_length = (size_t)tmp;
			LOG_VERBOSE("  output_length = %zu bytes",
				    opts->op.hash.output_length);
			break;
		}

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			LOG_VERBOSE("  subsystem = %s", optarg);
			break;

		case 't':
			opts->text_format = true;
			LOG_VERBOSE("  text_format = true");
			break;

		case ':':
			/* Missing argument for a known option */
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "hash");
			return -1;

		case '?':
		default:
			/* Unknown option */
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "hash");
			return -1;
		}
	}

	/* --list is requested */
	if (opts->show_list) {
		print_hash_algo_list();
		return 0;
	}

	/* Validate required options */
	if (!opts->show_help) {
		if (opts->op.hash.algo == HASH_ALGO_NONE) {
			ERROR("--algo is required for hash operation");
			PRINT_USE_LIST("algorithms");
			print_help_hint(prog_name, "hash");
			return -1;
		}

		if (!opts->input_filename) {
			ERROR("--input is required for hash operation");
			print_help_hint(prog_name, "hash");
			return -1;
		}

		if (opts->op.hash.output_length > 0 &&
		    !is_hash_algo_xof(opts->op.hash.algo)) {
			ERROR("--length option is only valid for XOF algorithms (e.g., SHAKE256)");
			PRINT_USE_LIST("algorithms");
			print_help_hint(prog_name, "hash");
			return -1;
		}
	}

	LOG_VERBOSE("Hash options parsed successfully");

	return 0;
}
