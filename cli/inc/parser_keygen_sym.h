/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_KEYGEN_SYM_H
#define CLI_PARSER_KEYGEN_SYM_H

#include "opt_parser.h"
#include "key_sym_mappings.h"
#include "utils.h"

int parse_keygen_sym_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name);
const char *cli_keygen_sym_inline_desc(void);
void cli_keygen_sym_help(void);
void cli_keygen_sym_help_common(void);

/* Unified list dispatcher */
void cli_keygen_sym_print_list(void);

#endif /* CLI_PARSER_KEYGEN_SYM_H */
