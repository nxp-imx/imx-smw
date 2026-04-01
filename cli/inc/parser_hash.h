/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_HASH_PARSER_H
#define CLI_HASH_PARSER_H

#include "opt_parser.h"

int parse_hash_options(int argc, char **argv, struct parsed_options *opts,
		       const char *prog_name);

#endif /* CLI_HASH_PARSER_H */
