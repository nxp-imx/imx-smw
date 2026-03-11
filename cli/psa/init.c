// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <psa/crypto.h>
#include "error_handler.h"
#include "logger.h"
#include "operations.h"

/**
 * @brief Initialize PSA Crypto backend
 */
enum cli_exit_code cli_backend_init(void)
{
	psa_status_t status = PSA_SUCCESS;

	status = psa_crypto_init();

	if (status != PSA_SUCCESS) {
		LOG_ERROR("psa_crypto_init() failed: %s (%d)\nDescription: %s",
			  cli_psa_status_to_name(status), (int)status,
			  cli_psa_status_to_description(status));
		return CLI_EXIT_INIT_FAILURE;
	}

	LOG_INFO("PSA Crypto initialized successfully");

	return CLI_EXIT_SUCCESS;
}
