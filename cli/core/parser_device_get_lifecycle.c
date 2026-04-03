// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "helper.h"
#include "lifecycle_table.h"
#include "opt_parser.h"
#include "parser_device_get_lifecycle.h"
#include "utils.h"

/* Short getopt options for get device lifecycle operation */
static const char *dev_get_lifecycle_short_opts = "ho:S:L::";

/* Define options for get device lifecycle operation */
static const struct option dev_get_lifecycle_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "list", no_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for dev-get-uuid operation
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
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Examples:\n");
	printf("  %s dev-get-lifecycle\n", prog_name);
	printf("  %s dev-get-lifecycle -o lifecycle.txt\n\n", prog_name);
}

/**
 * @brief Print list of available lifecycle values
 */
static void print_lifecycle_list(void)
{
	size_t i = 0;
	const struct lifecycle_info *info = NULL;

	printf("\n");
	printf("Available Device Lifecycle Values\n");
	printf("=================================\n\n");
	printf("%-20s %s\n", "Lifecycle", "Description");
	printf("%-20s %s\n", "---------", "-----------");

	for (; i < lifecycle_table_size; i++) {
		info = &lifecycle_table[i];

		printf("%-20s %s\n", info->name, info->description);
	}
	printf("\nNote: Actual support depends on the backend and subsystem capabilities.\n");
	printf("      The operation may fail at runtime if unsupported.\n\n");
}

/**
 * @brief Parse command-line options for dev-get-lifecycle operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_dev_get_lifecycle_options(int argc, char **argv,
				    struct parsed_options *opts,
				    const char *prog_name)
{
	int opt = 0;

	while ((opt = getopt_long(argc, argv, dev_get_lifecycle_short_opts,
				  dev_get_lifecycle_options, NULL)) != -1) {
		switch (opt) {
		case 0:
			opts->show_list = true;
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
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "dev-get-lifecycle"))
				return -1;
			break;

		default:
			print_help_hint(prog_name, "dev-get-lifecycle");
			return -1;
		}
	}

	if (opts->show_list)
		print_lifecycle_list();

	return 0;
}
