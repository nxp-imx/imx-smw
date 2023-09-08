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

int smw_utils_get_hmac_algo_id(const char *name,
			       enum smw_config_hmac_algo_id *id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return smw_utils_get_string_index(name, hmac_algo_names,
					  SMW_CONFIG_HMAC_ALGO_ID_NB, id);
}
