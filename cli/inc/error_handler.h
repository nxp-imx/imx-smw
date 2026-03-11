/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef CLI_ERROR_HANDLER_H
#define CLI_ERROR_HANDLER_H

#include <smw_status.h>
#include <psa/crypto.h>

/* ========================================================================
 * Error Table Definition Macro
 * ========================================================================
 */

/* Generic error info */
struct cli_error_info {
	int code;
	const char *name;
	const char *description;
};

#define ERROR(_code, _desc)                                                    \
	{                                                                      \
		.code = (_code), .name = #_code, .description = (_desc)        \
	}

/* SMW functions */
const char *cli_smw_status_to_name(enum smw_status_code status);
const char *cli_smw_status_to_description(enum smw_status_code status);

/* PSA functions */
const char *cli_psa_status_to_name(psa_status_t status);
const char *cli_psa_status_to_description(psa_status_t status);

#endif /* CLI_ERROR_HANDLER_H */
