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
#include "logger.h"
#include "opt_parser.h"
#include "parser_device_uuid.h"
#include "utils.h"

/* Short getopt options for DEVICE_UUID */
static const char *device_uuid_short_opts = ":ho:S:t";

/* Define options for DEVICE_UUID operation */
static const struct option device_uuid_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "text", no_argument, 0, 't' },
	{ "v", optional_argument, 0, 0 },
	{ "vv", optional_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for dev-get-uuid operation
 */
const char *cli_device_uuid_inline_desc(void)
{
	return "Get device UUID";
}

/**
 * @brief Display help information for dev-get-uuid operation
 */
void cli_device_uuid_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Device UUID Operation - SMW API\n\n");

	printf("Usage: %s dev-get-uuid [OPTIONS]\n\n", prog_name);

	printf("Description: ");
	printf("Get device UUID.\n\n");

	printf("Options:\n");
	printf("  -o, --output <file>       Output file\n");
	printf("  -t, --text                Write hex format\n");
	print_log_options_help(prog_name);
	print_help_option_help();
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n");

	printf("\nExamples:\n");
	printf("  %s dev-get-uuid\n", prog_name);
	printf("  %s dev-get-uuid -o uuid.bin\n", prog_name);
}

/**
 * @brief Parse command-line options for get_device_uuid operation
 *
 * @param argc      Argument count from command line
 * @param argv      Argument vector from command line
 * @param opts      Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_device_uuid_options(int argc, char **argv,
			      struct parsed_options *opts,
			      const char *prog_name)
{
	int opt = 0;
	int opt_index = 0;
	opterr = 0;

	/* This operation is only supported by SMW backend */
	if (prog_name && strstr(prog_name, "nxp_psa")) {
		LOG_ERROR("dev-get-uuid is not supported by PSA");
		cli_device_uuid_operation(NULL);
		return -1;
	}

	LOG_VERBOSE("Parsing dev-get-uuid options (argc=%d)", argc);

	while ((opt = getopt_long(argc, argv, device_uuid_short_opts,
				  device_uuid_options, &opt_index)) != -1) {
		switch (opt) {
		case 0:
			if (!strcmp(device_uuid_options[opt_index].name, "v")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "dev-get-uuid",
						     LOG_LEVEL_INFO))
					return -1;
			} else if (!strcmp(device_uuid_options[opt_index].name,
					   "vv")) {
				if (parse_log_option(opts, argc, argv,
						     prog_name, "dev-get-uuid",
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
				print_help_hint(prog_name, "dev-get-uuid");
				return -1;
			}
			LOG_VERBOSE("  output_filename = %s",
				    opts->output_filename);
			break;

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
			print_help_hint(prog_name, "dev-get-uuid");
			return -1;

		case '?':
		default:
			/* Unknown option */
			ERROR("Unknown option '%s'",
			      SAFE_ARGV_OPT(argv, "<unknown>"));
			print_help_hint(prog_name, "dev-get-uuid");
			return -1;
		}
	}

	LOG_VERBOSE("dev-get-uuid options parsed successfully");

	return 0;
}
