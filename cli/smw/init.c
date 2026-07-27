// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <smw_osal.h>
#include <smw_status.h>
#include <stdio.h>
#include "apis_dispatcher.h"
#include "common.h"
#include "error_handler.h"
#include "logger.h"

/**
 * @brief Initialize SMW (Security Middleware) backend
 */
enum cli_exit_code cli_backend_init(void)
{
	enum smw_status_code status = SMW_STATUS_OK;

	LOG_VERBOSE("Calling smw_osal_lib_init()");

	status = smw_osal_lib_init();

	if (!is_smw_api_success("smw_osal_lib_init", status))
		return CLI_EXIT_INIT_FAILURE;

	return CLI_EXIT_SUCCESS;
}
