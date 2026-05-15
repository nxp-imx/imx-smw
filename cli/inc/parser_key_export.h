/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_KEY_EXPORT_H
#define CLI_PARSER_KEY_EXPORT_H

#include "opt_parser.h"
#include "utils.h"

int parse_key_export_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name);
const char *cli_key_export_inline_desc(void);
void cli_key_export_help(void);
void cli_key_export_help_common(void);

#endif /* CLI_PARSER_KEY_EXPORT_H */
