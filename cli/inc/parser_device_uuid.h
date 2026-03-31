/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_DEVICE_PARSER_UUID_H
#define CLI_DEVICE_PARSER_UUID_H

#include "opt_parser.h"

int parse_device_uuid_options(int argc, char **argv,
			      struct parsed_options *opts,
			      const char *prog_name);
const char *cli_device_uuid_inline_desc(void);
void cli_device_uuid_help(void);

#endif /* CLI_DEVICE_PARSER_UUID_H */
