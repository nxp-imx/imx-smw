// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include "apis_dispatcher.h"
#include "helper.h"
#include "lifecycle_table.h"
#include "opt_parser.h"
#include "parser_device_set_lifecycle.h"
#include "utils.h"

/* Short getopt options for set device lifecycle operation */
static const char *dev_set_lifecycle_short_opts = "hl:S:L::";

/* Define options for set device lifecycle operation */
static const struct option dev_set_lifecycle_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "lifecycle", required_argument, 0, 'l' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "list", no_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for dev-set-lifecycle operation
 */
const char *cli_dev_set_lifecycle_inline_desc(void)
{
	return "Set device lifecycle";
}

/**
 * @brief Display help information for dev-set-lifecycle operation
 */
void cli_dev_set_lifecycle_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Set Device Lifecycle Operation - SMW API\n\n");

	printf("Usage: %s dev-set-lifecycle [OPTIONS]\n\n", prog_name);

	printf("Description: Set device lifecycle state.\n\n");

	printf("Warning: This operation is IRREVERSIBLE.");
	printf(" A confirmation prompt will be shown.\n\n");

	printf("Options:\n");
	printf("\n      --list                List all available lifecycle values\n\n");
	printf("  -l, --lifecycle <name>    Target lifecycle name to set\n");
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Examples:\n");
	printf("  %s dev-set-lifecycle --list\n", prog_name);
	printf("  %s dev-set-lifecycle -l OEM_CLOSED\n\n", prog_name);
}

/**
 * @brief Parse command-line options for dev-set-lifecycle operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_dev_set_lifecycle_options(int argc, char **argv,
				    struct parsed_options *opts,
				    const char *prog_name)
{
	int opt = 0;

	/* This operation is only supported by SMW backend */
	if (prog_name && strstr(prog_name, "nxp_psa")) {
		cli_dev_set_lifecycle_operation(NULL);
		return -1;
	}

	while ((opt = getopt_long(argc, argv, dev_set_lifecycle_short_opts,
				  dev_set_lifecycle_options, NULL)) != -1) {
		switch (opt) {
		case 0:
			opts->show_list = true;
			break;

		case 'h':
			opts->show_help = true;
			break;

		case 'l':
			opts->op.dev_set_lc.lifecycle_name = optarg;
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "dev-set-lifecycle"))
				return -1;
			break;

		default:
			print_help_hint(prog_name, "dev-set-lifecycle");
			return -1;
		}
	}

	/* Validate: --lifecycle is required unless --list or --help */
	if (!opts->show_list && !opts->show_help &&
	    !opts->op.dev_set_lc.lifecycle_name) {
		FPRINTF(stderr,
			"Error: --lifecycle <name> is required.\n"
			"       Use --list to see available lifecycles.\n");
		print_help_hint(prog_name, "dev-set-lifecycle");
		return -1;
	}

	if (opts->show_list)
		print_lifecycle_list();

	return 0;
}
