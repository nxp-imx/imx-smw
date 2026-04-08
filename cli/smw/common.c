// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "common.h"
#include "error_handler.h"
#include "helper.h"
#include "logger.h"

/* SMW subsystem name mapping (enum → API constant name) */
static const char *const smw_subsystem_names[] = {
	[SMW_SUBSYSTEM_NAME_NONE] = "SMW_SUBSYSTEM_NAME_NONE",
	[SMW_SUBSYSTEM_NAME_TEE] = "SMW_SUBSYSTEM_NAME_TEE",
	[SMW_SUBSYSTEM_NAME_SECO] = "SMW_SUBSYSTEM_NAME_SECO",
	[SMW_SUBSYSTEM_NAME_ELE] = "SMW_SUBSYSTEM_NAME_ELE",
};

/**
 * @brief Get SMW subsystem name string for logging
 *
 * @param subsystem: SMW subsystem enum value
 */
const char *cli_smw_get_subsystem_name(smw_subsystem_t subsystem)
{
	if (subsystem < ARRAY_SIZE(smw_subsystem_names) &&
	    smw_subsystem_names[subsystem])
		return smw_subsystem_names[subsystem];

	return "UNKNOWN_SUBSYSTEM";
}

/**
 * @brief Check SMW API status and log result
 *
 * @param func Function name
 * @param status SMW status code returned by the API
 */
bool is_smw_api_success(const char *func, enum smw_status_code status)
{
	bool ret = false;

	if (status != SMW_STATUS_OK) {
		LOG_ERROR("%s() failed: %s (%d)\nDescription: %s", func,
			  cli_smw_status_to_name(status), status,
			  cli_smw_status_to_description(status));
	} else {
		LOG_INFO("%s() succeeded: %s (%d)", func,
			 cli_smw_status_to_name(status), status);
		ret = true;
	}

	return ret;
}
