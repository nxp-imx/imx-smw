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
#include "hash_table_generated.h"
#include "helper.h"
#include "opt_parser.h"
#include "parser_hash.h"

#define MAX_HASH_LENGTH 1024

/* Short getopt options for HASH */
static const char *hash_short_opts = "ha:i:o:S:L::l:t";

/* Define options for HASH operation */
static const struct option hash_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "algo", required_argument, 0, 'a' },
	{ "input", required_argument, 0, 'i' },
	{ "output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "text", no_argument, 0, 't' },
	{ "length", required_argument, 0, 'l' },
	{ "list", no_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Print list of available hash algorithms
 */
static void print_hash_algo_list(void)
{
	size_t i;

	printf("\n");
	printf("Available Hash Algorithms\n");
	printf("=========================\n\n");
	printf("%-15s %-12s %s\n", "Algorithm", "Digest Size", "Description");
	printf("%-15s %-12s %s\n", "---------", "-----------", "-----------");

	for (i = 0; i < hash_algo_table_size; i++) {
		const struct hash_algo_info *info = &hash_algo_table[i];

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
	size_t i;

	/* Validate input */
	if (!algo_str || algo_str[0] == '\0') {
		FPRINTF(stderr, "Error: Hash algorithm cannot be empty\n");
		return HASH_ALGO_NONE;
	}

	/* Reject if it looks like an option */
	if (algo_str[0] == '-') {
		FPRINTF(stderr,
			"Error: Hash algorithm cannot start with '-'.\n");
		FPRINTF(stderr,
			"       Use --list to see available algorithms\n");
		return HASH_ALGO_NONE;
	}

	/* Search in the hash algorithm table */
	for (i = 0; i < hash_algo_table_size; i++) {
		if (!strcasecmp(algo_str, hash_algo_table[i].name))
			return hash_algo_table[i].algo;
	}

	FPRINTF(stderr, "Error: Unknown hash algorithm '%s'\n", algo_str);
	FPRINTF(stderr, "       Use --list to see available algorithms\n");
	return HASH_ALGO_NONE;
}

/**
 * @brief Parse command-line options for HASH operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_hash_options(int argc, char **argv, struct parsed_options *opts,
		       const char *prog_name)
{
	int opt = 0;

	while ((opt = getopt_long(argc, argv, hash_short_opts, hash_options,
				  NULL)) != -1) {
		switch (opt) {
		case 0:
			opts->show_list = true;
			break;
		case 'h':
			opts->show_help = true;
			break;

		case 'a':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --algo requires an argument\n");
				print_help_hint(prog_name, "hash");
				return -1;
			}
			opts->op.hash.algo = parse_hash_algo(optarg);
			if (opts->op.hash.algo == HASH_ALGO_NONE) {
				print_help_hint(prog_name, "hash");
				return -1;
			}
			break;

		case 'i':
			opts->input_filename =
				parse_file_opt(optarg, "Input filename");
			if (!opts->input_filename) {
				print_help_hint(prog_name, "hash");
				return -1;
			}
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name, "hash");
				return -1;
			}
			break;

		case 'l':
			char *endptr = NULL;
			unsigned long tmp = 0;

			if (!optarg) {
				FPRINTF(stderr,
					"Error: --length requires an argument\n");
				print_help_hint(prog_name, "hash");
				return -1;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);

			if (errno || endptr == optarg || *endptr != '\0') {
				FPRINTF(stderr,
					"Error: Invalid length value '%s'\n",
					optarg);
				print_help_hint(prog_name, "hash");
				return -1;
			}

			if (!tmp || tmp > MAX_HASH_LENGTH) {
				FPRINTF(stderr,
					"Error: Length must be between 1 and 1024 bytes\n");
				print_help_hint(prog_name, "hash");
				return -1;
			}

			opts->op.hash.output_length = (size_t)tmp;
			break;
		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "hash"))
				return -1;
			break;

		case 't':
			opts->text_format = true;
			break;

		default:
			print_help_hint(prog_name, "hash");
			return -1;
		}
	}

	/* --list is requested */
	if (opts->show_list) {
		print_hash_algo_list();
		return 0; /* No operation to perform */
	}

	/* Validate required options */
	if (!opts->show_help) {
		if (opts->op.hash.algo == HASH_ALGO_NONE) {
			FPRINTF(stderr,
				"Error: --algo is required for hash operation\n");
			FPRINTF(stderr,
				"       Use --list to see available algorithms\n");
			print_help_hint(prog_name, "hash");
			return -1;
		}

		if (!opts->input_filename) {
			FPRINTF(stderr,
				"Error: --input is required for hash operation\n");
			print_help_hint(prog_name, "hash");
			return -1;
		}

		if (opts->op.hash.output_length > 0 &&
		    !is_hash_algo_xof(opts->op.hash.algo)) {
			FPRINTF(stderr,
				"Error: --length option is only valid for XOF algorithms (e.g., SHAKE256)\n");
			FPRINTF(stderr,
				"       Use --list to see available algorithms\n");
			print_help_hint(prog_name, "hash");
			return -1;
		}
	}

	return 0;
}
