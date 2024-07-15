// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
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
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_224] = "SHA3_224",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_256] = "SHA3_256",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_384] = "SHA3_384",
	[SMW_CONFIG_HASH_ALGO_ID_SHA3_512] = "SHA3_512",
	[SMW_CONFIG_HASH_ALGO_ID_SM3] = "SM3"
};

int smw_utils_hash_algo_names(char **start, char *end, unsigned long *bitmap)
{
	int status =
		smw_config_read_strings(start, end, bitmap, hash_algo_names,
					SMW_CONFIG_HASH_ALGO_ID_NB);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	return status;
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

	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
