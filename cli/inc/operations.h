/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_OPERATIONS_H
#define CLI_OPERATIONS_H

#include <smw_crypto.h>
#include <psa/crypto.h>
#include <limits.h>
#include "opt_parser.h"
#include "logger.h"

/* CLI exit codes */
enum cli_exit_code {
	CLI_EXIT_SUCCESS = 0,	    /* Operation completed successfully */
	CLI_EXIT_INIT_FAILURE,	    /* Backend/system initialization failed */
	CLI_EXIT_OPERATION_FAILURE, /* Crypto operation or file I/O failed */
	CLI_EXIT_NOT_IMPLEMENTED /* Operation not implemented in this build */
};

/* Backend initialization */
enum cli_exit_code cli_backend_init(void);

/* RNG operation functions */
enum cli_exit_code cli_rng_operation(struct parsed_options *args);
void cli_rng_help(void);
const char *cli_rng_inline_desc(void);
void cli_rng_help_common(void);

/* More operation declarations here as we implement them */

#endif /* CLI_OPERATIONS_H */
