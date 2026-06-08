/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_ENCRYPT_H
#define CLI_PARSER_ENCRYPT_H

#include "opt_parser.h"

int parse_encrypt_options(int argc, char **argv, struct parsed_options *opts,
			  const char *prog_name);
const char *cli_encrypt_inline_desc(void);
void cli_encrypt_help(void);

void cli_encrypt_help_common(void);

int parse_decrypt_options(int argc, char **argv, struct parsed_options *opts,
			  const char *prog_name);
const char *cli_decrypt_inline_desc(void);
void cli_decrypt_help(void);

#endif /* CLI_PARSER_ENCRYPT_H */
