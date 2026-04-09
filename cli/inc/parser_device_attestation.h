/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef PARSER_DEVICE_ATTESTATION_H
#define PARSER_DEVICE_ATTESTATION_H

#include "opt_parser.h"

int parse_device_attestation_options(int argc, char **argv,
				     struct parsed_options *opts,
				     const char *prog_name);
void cli_device_attestation_help(void);
const char *cli_device_attestation_inline_desc(void);

#endif /* PARSER_DEVICE_ATTESTATION_H */
