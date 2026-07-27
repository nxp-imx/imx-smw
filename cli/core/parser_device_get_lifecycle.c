// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "cli_print.h"
#include "helper.h"
#include "lifecycle_table.h"
#include "logger.h"
#include "opt_parser.h"
#include "parser_device_get_lifecycle.h"
#include "utils.h"

/* Short getopt options for get device lifecycle operation */
static const char *dev_get_lifecycle_short_opts = ":ho:S:";

/* Define options for get device lifecycle operation */
static const struct option dev_get_lifecycle_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "list", no_argument, 0, 0 },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for dev-get-lifecycle operation
 */
const char *cli_dev_get_lifecycle_inline_desc(void)
{
	return "Get device lifecycle";
}

/**
 * @brief Display help information for dev-get-lifecycle operation
 */
void cli_dev_get_lifecycle_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Get Device Lifecycle Operation - SMW API\n\n");

	printf("Usage: %s dev-get-lifecycle [OPTIONS]\n\n", prog_name);

	printf("Description: Get current device lifecycle state.\n\n");

	printf("Options:\n");
	printf("\n      --list                List all available lifecycle values\n\n");
	printf("  -o, --output <file>       Output file\n");
	print_log_options_help(prog_name);
	print_help_option_help();
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n");

	printf("\nExamples:\n");
	printf("  %s dev-get-lifecycle\n", prog_name);
	printf("  %s dev-get-lifecycle -o lifecycle.txt\n", prog_name);
}

/**
 * @brief Parse command-line options for dev-get-lifecycle operation
 *
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param opts      Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_dev_get_lifecycle_options(int argc, char **argv,
				    struct parsed_options *opts,
				    const char *prog_name)
{
	int opt = 0;
	int opt_index = 0;
	opterr = 0;

	/* This operation is only supported by SMW backend */
	if (prog_name && strstr(prog_name, "nxp_psa")) {
		LOG_ERROR("dev-get-lifecycle is not supported by PSA");
		cli_dev_get_lifecycle_operation(NULL);
		return -1;
	}

	LOG_VERBOSE("Parsing dev-get-lifecycle options (argc=%d)", argc);

	while ((opt = getopt_long(argc, argv, dev_get_lifecycle_short_opts,
				  dev_get_lifecycle_options, &opt_index)) !=
	       -1) {
		switch (opt) {
		case 0:
			if (!strcmp(dev_get_lifecycle_options[opt_index].name,
				    "list")) {
				opts->show_list = true;
				LOG_VERBOSE("  show_list = true");
			} else if (!strcmp(dev_get_lifecycle_options[opt_index]
						   .name,
					   "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name,
						     "dev-get-lifecycle",
						     LOG_LEVEL_INFO))
					return -1;
			} else if (!strcmp(dev_get_lifecycle_options[opt_index]
						   .name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name,
						     "dev-get-lifecycle",
						     LOG_LEVEL_VERBOSE))
					return -1;
			}
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name, "dev-get-lifecycle");
				return -1;
			}
			LOG_VERBOSE("  output_filename = %s",
				    opts->output_filename);
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			LOG_VERBOSE("  subsystem = %s", optarg);
			break;

		case ':':
			/* Missing argument for a known option */
			ERROR("Option '%s' requires an argument",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "dev-get-lifecycle");
			return -1;

		case '?':
		default:
			/* Unknown option */
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "dev-get-lifecycle");
			return -1;
		}
	}

	if (opts->show_list) {
		LOG_VERBOSE("Printing lifecycle list");
		print_lifecycle_list();
	}

	LOG_VERBOSE("dev-get-lifecycle options parsed successfully");

	return 0;
}
