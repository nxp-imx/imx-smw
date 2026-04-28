/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_KEYGEN_ASYM_H
#define CLI_PARSER_KEYGEN_ASYM_H

#include "opt_parser.h"
#include "key_asym_mappings.h"
#include "utils.h"

int parse_keygen_asym_options(int argc, char **argv,
			      struct parsed_options *opts,
			      const char *prog_name);
const char *cli_keygen_asym_inline_desc(void);
void cli_keygen_asym_help(void);
void cli_keygen_asym_help_common(void);

/* Unified list dispatcher */
void cli_keygen_asym_print_list(void);

#endif /* CLI_PARSER_KEYGEN_ASYM_H */
