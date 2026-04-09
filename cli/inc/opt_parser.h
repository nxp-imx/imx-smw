/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_OPT_PARSER_H
#define CLI_OPT_PARSER_H

#include <getopt.h>
#include <stdbool.h>
#include "hash_algo_enum.h"
#include "logger.h"

/* Operation types */
enum operation {
	OP_NONE = 0,
	OP_RNG,
	OP_HASH,
	OP_DEVICE_UUID,
	OP_DEVICE_LIFECYCLE,
	OP_DEVICE_ATTESTATION
};

/* RNG-specific options */
struct rng {
	size_t size;
};

/* Hash-specific options */
struct hash {
	enum hash_algo algo;
	size_t output_length;
};

/* Device attestation-specific options */
struct dev_att {
	char *challenge_filename;
};

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
	bool text_format;

	/* Logging options */
	enum log_dest log_dest;
	char *log_filename;

	/* Operation-specific options */
	union {
		struct rng rng;
		struct hash hash;
		struct dev_att dev_att;
	} op;
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
