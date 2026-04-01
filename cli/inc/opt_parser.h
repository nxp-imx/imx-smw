/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_OPT_PARSER_H
#define CLI_OPT_PARSER_H

#include <stdbool.h>
#include <getopt.h>
#include "hash_algo_enum.h"
#include "logger.h"

/* Operation types */
enum operation { OP_NONE = 0, OP_RNG, OP_HASH };

/* Parsed options structure */
struct parsed_options {
	enum operation operation;
	const char *operation_name;
	bool show_help;
	bool show_list;

	/* Common options */
	char *output_filename;
	char *input_filename;
	smw_subsystem_t subsystem;

	/* Logging options */
	enum log_dest log_dest;
	char *log_filename;

	/* Operation-specific options */
	union {
		/* RNG specific */
		struct {
			size_t size;
			bool text_format;
		};

		/* Hash specific */
		struct {
			enum hash_algo hash_algo;
			size_t hash_output_length;
		};
	};
};

/* Shared Functions between op_parsers */
smw_subsystem_t parse_subsystem(const char *subsystem_str);
char *parse_file_opt(const char *src, const char *field_name);
int parse_log_option(struct parsed_options *opts, int argc, char **argv,
		     const char *prog_name, const char *operation);
void print_help_hint(const char *prog_name, const char *operation);

/* Function prototypes */
enum operation parse_cli_options(int argc, char **argv,
				 struct parsed_options *opts);
void opt_parser_cleanup(struct parsed_options *opts);

#endif /* CLI_OPT_PARSER_H */
