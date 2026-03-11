// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "common.h"
#include "error_handler.h"
#include "logger.h"

/**
 * @brief Check PSA API status and log result
 *
 * @param func Function name
 * @param status PSA status code returned by the API
 */
bool is_psa_api_success(const char *func, psa_status_t status)
{
	bool ret = false;

	if (status != PSA_SUCCESS) {
		LOG_ERROR("%s() failed: %s (%d)\nDescription: %s", func,
			  cli_psa_status_to_name(status), (int)status,
			  cli_psa_status_to_description(status));
	} else {
		LOG_INFO("%s() succeeded: %s (%d)", func,
			 cli_psa_status_to_name(status), (int)status);
		ret = true;
	}

	return ret;
}
