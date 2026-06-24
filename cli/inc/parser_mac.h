/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_MAC_H
#define CLI_PARSER_MAC_H

#include "opt_parser.h"

/* mac (compute) */
int parse_mac_options(int argc, char **argv, struct parsed_options *opts,
		      const char *prog_name);
const char *cli_mac_inline_desc(void);
void cli_mac_help(void);
void cli_mac_help_common(void);

/* mac-verify */
int parse_mac_verify_options(int argc, char **argv, struct parsed_options *opts,
			     const char *prog_name);
const char *cli_mac_verify_inline_desc(void);
void cli_mac_verify_help(void);
void cli_mac_verify_help_common(void);

/*
 * Parse the combined algo string (e.g. "HMAC-SHA256") into
 * base algorithm and optional hash parts.
 */
int mac_parse_algo_string(const char *algo_str, char *base_algo,
			  size_t base_size, char *hash_out, size_t hash_size);

#endif /* CLI_PARSER_MAC_H */
