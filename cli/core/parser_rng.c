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
#include "helper.h"
#include "opt_parser.h"
#include "parser_rng.h"

/* Short getopt options string for RNG */
static const char *rng_short_opts = "hs:o:S:L::t";

/* Define options for RNG operation */
static const struct option rng_options[] = {
	{ "help", no_argument, 0, 'h' },
	{ "size", required_argument, 0, 's' },
	{ "output", required_argument, 0, 'o' },
	{ "subsystem", required_argument, 0, 'S' },
	{ "log", optional_argument, 0, 'L' },
	{ "text", no_argument, 0, 't' },
	{ 0, 0, 0, 0 }
};

/**
 * @brief Parse command-line options for RNG operation
 *
 * @param argc Argument count from command line
 * @param argv Argument vector from command line
 * @param opts Pointer to parsed_options structure to populate
 * @param prog_name The program name (executable)
 */
int parse_rng_options(int argc, char **argv, struct parsed_options *opts,
		      const char *prog_name)
{
	int opt = 0;
	char *endptr = NULL;
	unsigned long tmp = 0;

	while ((opt = getopt_long(argc, argv, rng_short_opts, rng_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'h':
			opts->show_help = true;
			break;

		case 's':
			/* Validate it's not another option */
			if (optarg[0] == '-') {
				FPRINTF(stderr,
					"Error: Size value cannot start with '-'.\n");
				FPRINTF(stderr,
					"       Expected a positive number.\n");
				print_help_hint(prog_name, "rng");
				return -1;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 0);

			if (errno != 0 || endptr == optarg || *endptr != '\0') {
				FPRINTF(stderr,
					"Error: Invalid size value '%s'\n",
					optarg);
				print_help_hint(prog_name, "rng");
				return -1;
			}

			/* Validate size fits in 32-bit unsigned int */
			if (tmp > UINT32_MAX) {
				FPRINTF(stderr,
					"Error: Size exceeds maximum %u\n",
					UINT32_MAX);
				print_help_hint(prog_name, "rng");
				return -1;
			}

			opts->size = (size_t)tmp;
			if ((unsigned long)opts->size != tmp) {
				FPRINTF(stderr,
					"Error: Size value too large for this platform\n");
				print_help_hint(prog_name, "rng");
				return -1;
			}
			break;

		case 'o':
			opts->output_filename =
				parse_file_opt(optarg, "Output filename");
			if (!opts->output_filename) {
				print_help_hint(prog_name, "rng");
				return -1;
			}
			break;

		case 'S':
			opts->subsystem = parse_subsystem(optarg);
			break;

		case 'L':
			if (parse_log_option(opts, argc, argv, prog_name,
					     "rng") != 0)
				return -1;
			break;

		case 't':
			opts->text_format = true;
			break;

		default:
			print_help_hint(prog_name, "rng");
			return -1;
		}
	}

	/* Validate required options */
	if (!opts->show_help && !opts->size) {
		FPRINTF(stderr,
			"Error: --size is required for RNG operation\n");
		print_help_hint(prog_name, "rng");
		return -1;
	}

	return 0;
}
