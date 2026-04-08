// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_osal.h>
#include <smw_status.h>
#include <stdio.h>
#include "apis_dispatcher.h"
#include "error_handler.h"
#include "logger.h"

/**
 * @brief Initialize SMW (Security Middleware) backend
 */
enum cli_exit_code cli_backend_init(void)
{
	enum smw_status_code status = SMW_STATUS_OK;

	status = smw_osal_lib_init();

	if (status != SMW_STATUS_OK) {
		LOG_ERROR("smw_osal_lib_init() failed: %s (%d)\nDescription: %s",
			  cli_smw_status_to_name(status), status,
			  cli_smw_status_to_description(status));
		return CLI_EXIT_INIT_FAILURE;
	}

	LOG_INFO("SMW library initialized successfully");

	return CLI_EXIT_SUCCESS;
}
