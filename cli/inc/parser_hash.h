/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_HASH_H
#define CLI_PARSER_HASH_H

#include "opt_parser.h"

int parse_hash_options(int argc, char **argv, struct parsed_options *opts,
		       const char *prog_name);
const char *cli_hash_inline_desc(void);
void cli_hash_help(void);
void cli_hash_help_common(void);

#endif /* CLI_PARSER_HASH_H */
