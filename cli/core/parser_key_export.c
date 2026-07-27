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
#include "helper.h"
#include "logger.h"
#include "opt_parser.h"
#include "parser_key_export.h"
#include "utils.h"

/* Short getopt options for key export */
static const char *key_export_short_opts = ":hi:o:S:dp";

/* Define options for key export operation */
static const struct option key_export_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "id", required_argument, 0, 'i' },
	{ "pub-output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "der", no_argument, 0, 'd' },
	{ "pem", no_argument, 0, 'p' },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
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
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n");
	print_log_options_help(prog_name);
	print_help_option_help();
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
		ERROR("Invalid key ID value '%s'", id_str);
		return -1;
	}

	if (tmp > UINT32_MAX || !tmp) {
		ERROR("Key ID must be between 1 and %u", UINT32_MAX);
		return -1;
	}

	*id = (unsigned int)tmp;
	return 0;
}

/**
 * @brief Parse command-line options for key export operation
 *
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param opts      Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_key_export_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name)
{
	int opt = 0;
	int option_index = 0;
	bool id_specified = false;
	opterr = 0;

	LOG_VERBOSE("Parsing key-export options (argc=%d)", argc);

	while ((opt = getopt_long(argc, argv, key_export_short_opts,
				  key_export_options, &option_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(key_export_options[option_index].name,
				    "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "key-export",
						     LOG_LEVEL_INFO))
					return -1;
			} else if (!strcmp(key_export_options[option_index].name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "key-export",
						     LOG_LEVEL_VERBOSE))
					return -1;
			}
			break;

		case 'h':
			opts->show_help = true;
			LOG_VERBOSE("  show_help = true");
			break;

		case 'i':
			if (!optarg) {
				ERROR("--id requires an argument");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			if (parse_key_id(optarg, &opts->op.key_export.key_id)) {
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			id_specified = true;
			LOG_VERBOSE("  key_id = 0x%08x (%u)",
				    opts->op.key_export.key_id,
				    opts->op.key_export.key_id);
			break;

		case 'o':
			if (!optarg || optarg[0] == '\0' || optarg[0] == '-') {
				ERROR("--pub-output requires an argument");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			opts->op.key_export.key_file =
				parse_file_opt(optarg, "Public key output");
			if (!opts->op.key_export.key_file) {
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			LOG_VERBOSE("  key_file = %s",
				    opts->op.key_export.key_file);
			break;

		case 'd':
			if (opts->op.key_export.use_pem) {
				ERROR("--der and --pem are mutually exclusive");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			opts->op.key_export.use_der = true;
			LOG_VERBOSE("  use_der = true");
			break;

		case 'p':
			if (opts->op.key_export.use_der) {
				ERROR("--der and --pem are mutually exclusive");
				print_help_hint(prog_name, "key-export");
				return -1;
			}
			opts->op.key_export.use_pem = true;
			LOG_VERBOSE("  use_pem = true");
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			LOG_VERBOSE("  subsystem = %s", optarg);
			break;

		case ':':
			/* Missing argument for a known option */
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "key-export");
			return -1;

		case '?':
		default:
			/* Unknown option */
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "key-export");
			return -1;
		}
	}

	/* Validate required options */
	if (!opts->show_help) {
		if (!id_specified) {
			ERROR("--id is required for key export");
			print_help_hint(prog_name, "key-export");
			return -1;
		}

		if (!opts->op.key_export.key_file) {
			ERROR("--pub-output is required for key export");
			print_help_hint(prog_name, "key-export");
			return -1;
		}
	}

	LOG_VERBOSE("key-export options parsed successfully");

	return 0;
}
