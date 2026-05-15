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
#include "helper.h"
#include "opt_parser.h"
#include "parser_key_export.h"
#include "utils.h"

/* Short getopt options for key export */
static const char *key_export_short_opts = "hi:o:S:L::dp";

/* Define options for key export operation */
static const struct option key_export_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "id", required_argument, 0, 'i' },
	{ "pub-output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "der", no_argument, 0, 'd' },
	{ "pem", no_argument, 0, 'p' },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for key export operation
 */
const char *cli_key_export_inline_desc(void)
{
	return "Export a key from the secure subsystem";
}

/**
 * @brief Print common key export help (backend-agnostic)
 */
void cli_key_export_help_common(void)
{
	const char *prog_name = get_program_name();

	printf("Usage: %s key-export [OPTIONS]\n\n", prog_name);
	printf("Export a key from the secure subsystem.\n\n");

	printf("Options:\n");
	printf("  -i, --id <id>             Key ID to export");
	printf(" (required, decimal or hex with 0x prefix)\n");
	printf("  -o, --pub-output <file>   Output file for public key\n");
	printf("  -d, --der                 Export key in DER format\n");
	printf("  -p, --pem                 Export key in PEM format\n");
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
}

/**
 * @brief Parse key ID string into unsigned int
 *
 * @param id_str String representing the key ID
 * @param id Pointer to store parsed ID
 */
static int parse_key_id(const char *id_str, unsigned int *id)
{
	char *endptr = NULL;
	unsigned long tmp = 0;

	if (!id_str || !id)
		return -1;

	errno = 0;
	tmp = strtoul(id_str, &endptr, 0);

	if (errno || endptr == id_str || *endptr != '\0') {
		FPRINTF(stderr, "Error: Invalid key ID value '%s'\n", id_str);
		return -1;
	}

	if (tmp > UINT32_MAX || !tmp) {
		FPRINTF(stderr, "Error: Key ID must be between 1 and %u\n",
			UINT32_MAX);
		return -1;
	}

	*id = (unsigned int)tmp;
	return 0;
}

/**
 * @brief Parse command-line options for key export operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_key_export_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name)
{
	int opt = 0;
	int option_index = 0;
	bool id_specified = false;

	while ((opt = getopt_long(argc, argv, key_export_short_opts,
				  key_export_options, &option_index)) != -1) {
		switch (opt) {
		case 'h':
			opts->show_help = true;
			break;

		case 'i':
			if (!optarg) {
				FPRINTF(stderr,
					"Error: --id requires an argument\n");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			if (parse_key_id(optarg, &opts->op.key_export.key_id)) {
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			id_specified = true;
			break;

		case 'o':
			if (!optarg || optarg[0] == '\0' || optarg[0] == '-') {
				FPRINTF(stderr,
					"Error: --pub-output requires an argument\n");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			opts->op.key_export.key_file =
				parse_file_opt(optarg, "Public key output");
			if (!opts->op.key_export.key_file) {
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			break;

		case 'd':
			if (opts->op.key_export.use_pem) {
				FPRINTF(stderr,
					"Error: --der and --pem are mutually exclusive\n");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			opts->op.key_export.use_der = true;
			break;

		case 'p':
			if (opts->op.key_export.use_der) {
				FPRINTF(stderr,
					"Error: --der and --pem are mutually exclusive\n");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			opts->op.key_export.use_pem = true;
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "key-export"))
				return -1;
			break;

		default:
			print_help_hint(prog_name, "key-export");
			return -1;
		}
	}

	/* Validate required options */
	if (!opts->show_help) {
		if (!id_specified) {
			FPRINTF(stderr,
				"Error: --id is required for key export\n");
			print_help_hint(prog_name, "key-export");
			return -1;
		}

		if (!opts->op.key_export.key_file) {
			FPRINTF(stderr,
				"Error: --pub-output is required for key export\n");
			print_help_hint(prog_name, "key-export");
			return -1;
		}
	}

	return 0;
}
