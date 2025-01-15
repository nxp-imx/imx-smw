// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_status.h"

#include "common.h"

static const char *const mac_algo_strings[] = {
	[SMW_CONFIG_MAC_ALGO_ID_CMAC] = "CMAC",
	[SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED] = "CMAC_TRUNCATED",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC] = "HMAC",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED] = "HMAC_TRUNCATED",
};

int read_mac_algo_strings(char **start, char *end, unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, mac_algo_strings,
					SMW_CONFIG_MAC_ALGO_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	return status;
}
