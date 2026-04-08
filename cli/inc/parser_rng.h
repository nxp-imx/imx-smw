/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_RNG_H
#define CLI_PARSER_RNG_H

#include "opt_parser.h"

int parse_rng_options(int argc, char **argv, struct parsed_options *opts,
		      const char *prog_name);
const char *cli_rng_inline_desc(void);
void cli_rng_help_common(void);

#endif /* CLI_PARSER_RNG_H */
