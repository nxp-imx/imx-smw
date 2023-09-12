// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "config.h"
#include "debug.h"
#include "name.h"

static const char *const hmac_algo_names[] = {
	[SMW_CONFIG_HMAC_ALGO_ID_MD5] = "MD5",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA1] = "SHA1",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA224] = "SHA224",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA256] = "SHA256",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA384] = "SHA384",
	[SMW_CONFIG_HMAC_ALGO_ID_SHA512] = "SHA512",
	[SMW_CONFIG_HMAC_ALGO_ID_SM3] = "SM3"
};

static const char *const mac_algo_names[] = {
	[SMW_CONFIG_MAC_ALGO_ID_CMAC] = "CMAC",
	[SMW_CONFIG_MAC_ALGO_ID_CMAC_TRUNCATED] = "CMAC_TRUNCATED",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC] = "HMAC",
	[SMW_CONFIG_MAC_ALGO_ID_HMAC_TRUNCATED] = "HMAC_TRUNCATED",
};

int smw_utils_get_hmac_algo_id(const char *name,
			       enum smw_config_hmac_algo_id *id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return smw_utils_get_string_index(name, hmac_algo_names,
					  SMW_CONFIG_HMAC_ALGO_ID_NB, id);
}

int smw_utils_get_mac_algo_id(const char *name, enum smw_config_mac_algo_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;
	if (!name)
		*id = SMW_CONFIG_MAC_ALGO_ID_INVALID;
	else
		status = smw_utils_get_string_index(name, mac_algo_names,
						    SMW_CONFIG_MAC_ALGO_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_mac_algo_names(char **start, char *end, unsigned long *bitmap)
{
	return smw_config_read_names(start, end, bitmap, mac_algo_names,
				     SMW_CONFIG_MAC_ALGO_ID_NB);
}
