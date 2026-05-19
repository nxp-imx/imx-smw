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
#include "opt_parser.h"
#include "parser_device_attestation.h"
#include "utils.h"

/* Short getopt options for DEVICE_ATTESTATION */
static const char *device_attestation_short_opts = "ho:c:S:L::t";

/* Define options for DEVICE_ATTESTATION operation */
static const struct option device_attestation_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "output", required_argument, 0, 'o' },
	{ "challenge", required_argument, 0, 'c' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "text", no_argument, 0, 't' },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Get inline description for dev-get-attestation operation
 */
const char *cli_device_attestation_inline_desc(void)
{
	return "Get device attestation certificate";
}

/**
 * @brief Display help information for dev-get-attestation operation
 */
void cli_device_attestation_help(void)
{
	const char *prog_name = get_program_name();

	printf("\n");
	print_tool_banner();
	printf("Device Attestation Operation - SMW API\n\n");

	printf("Usage: %s dev-get-attestation [OPTIONS]\n\n", prog_name);

	printf("Description: Get device attestation certificate.\n\n");

	printf("Options:\n");
	printf("  -o, --output <file>       Output file\n");
	printf("  -c, --challenge <file>    Challenge input file\n");
	printf("                            If not specified, uses current date/time\n");
	printf("  -t, --text                Write hex format\n");
	printf("  -L, --log <dest>          Enable session logging");
	printf(" (%s log --help for info)\n", prog_name);
	printf("  -h, --help                Show help\n");
	printf("  -S, --subsystem <name>    Force subsystem (ELE/TEE/SECO)\n\n");

	printf("Examples:\n");
	printf("  %s dev-get-attestation\n", prog_name);
	printf("  %s dev-get-attestation -o cert.bin -c challenge.bin\n\n",
	       prog_name);
}

/**
 * @brief Parse command-line options for dev-get-attestation operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_device_attestation_options(int argc, char **argv,
				     struct parsed_options *opts,
				     const char *prog_name)
{
	int opt = 0;

	/* This operation is only supported by SMW backend */
	if (prog_name && strstr(prog_name, "nxp_psa")) {
		cli_device_attestation_operation(NULL);
		return -1;
	}

	while ((opt = getopt_long(argc, argv, device_attestation_short_opts,
				  device_attestation_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			opts->show_help = true;
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name,
						"dev-get-attestation");
				return -1;
			}
			break;

		case 'c':
			opts->op.dev_att.challenge_filename =
				parse_file_opt(optarg, "Challenge filename");
			if (!opts->op.dev_att.challenge_filename) {
				print_help_hint(prog_name,
						"dev-get-attestation");
				return -1;
			}
			break;

		case 't':
			opts->text_format = true;
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "dev-get-attestation"))
				return -1;
			break;

		default:
			print_help_hint(prog_name, "dev-get-attestation");
			return -1;
		}
	}

	return 0;
}
