/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_PARSER_DEVICE_GET_LIFECYCLE_H
#define CLI_PARSER_DEVICE_GET_LIFECYCLE_H

#include "opt_parser.h"

int parse_dev_get_lifecycle_options(int argc, char **argv,
				    struct parsed_options *opts,
				    const char *prog_name);
const char *cli_dev_get_lifecycle_inline_desc(void);
void cli_dev_get_lifecycle_help(void);

#endif /* CLI_PARSER_DEVICE_GET_LIFECYCLE_H */
