// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <psa/crypto.h>
#include <stdio.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "logger.h"

/**
 * @brief Initialize PSA Crypto backend
 */
enum cli_exit_code cli_backend_init(void)
{
	psa_status_t status = PSA_SUCCESS;

	LOG_VERBOSE("Calling psa_crypto_init()");

	status = psa_crypto_init();

	if (!is_psa_api_success("psa_crypto_init", status))
		return CLI_EXIT_INIT_FAILURE;

	return CLI_EXIT_SUCCESS;
}
