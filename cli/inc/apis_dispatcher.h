/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_APIS_DISPATCHER_H
#define CLI_APIS_DISPATCHER_H

#include <limits.h>
#include <psa/crypto.h>
#include <smw_crypto.h>
#include "logger.h"
#include "opt_parser.h"

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

/* Hash operation functions */
enum cli_exit_code cli_hash_operation(struct parsed_options *args);

/* Device UUID operation functions */
enum cli_exit_code cli_device_uuid_operation(struct parsed_options *args);

/* Device lifecycle operation functions */
enum cli_exit_code cli_dev_get_lifecycle_operation(struct parsed_options *args);

/* Device set lifecycle operation functions */
enum cli_exit_code cli_dev_set_lifecycle_operation(struct parsed_options *args);

/* Device attestation operation functions */
enum cli_exit_code
cli_device_attestation_operation(struct parsed_options *args);

/* More operation declarations here as we implement them */

#endif /* CLI_APIS_DISPATCHER_H */
