// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "config.h"
#include "debug.h"
#include "name.h"

static const char *const hash_algo_names[] = {
	[SMW_CONFIG_HASH_ALGO_ID_MD5] = "MD5",
	[SMW_CONFIG_HASH_ALGO_ID_SHA1] = "SHA1",
	[SMW_CONFIG_HASH_ALGO_ID_SHA224] = "SHA224",
	[SMW_CONFIG_HASH_ALGO_ID_SHA256] = "SHA256",
	[SMW_CONFIG_HASH_ALGO_ID_SHA384] = "SHA384",
	[SMW_CONFIG_HASH_ALGO_ID_SHA512] = "SHA512",
	[SMW_CONFIG_HASH_ALGO_ID_SM3] = "SM3"
};

int smw_utils_hash_algo_names(char **start, char *end, unsigned long *bitmap)
{
	return smw_config_read_names(start, end, bitmap, hash_algo_names,
				     SMW_CONFIG_HASH_ALGO_ID_NB);
}

int smw_utils_get_hash_algo_id(const char *name,
			       enum smw_config_hash_algo_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_CONFIG_HASH_ALGO_ID_INVALID;
	else
		status = smw_utils_get_string_index(name, hash_algo_names,
						    SMW_CONFIG_HASH_ALGO_ID_NB,
						    id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
