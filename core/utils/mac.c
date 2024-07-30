// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "config.h"
#include "debug.h"
#include "utils.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_CONFIG_MAC_ALGO_ID_OFFSET                                          \
	(SMW_MAC_ALGO_NAME_CMAC - SMW_CONFIG_MAC_ALGO_ID_CMAC)

int smw_utils_get_mac_algo_id(smw_mac_algo_t name,
			      enum smw_config_mac_algo_id *id)
{
	int status = SMW_STATUS_UNKNOWN_ALGO_NAME;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name == SMW_MAC_ALGO_NAME_NONE) {
		*id = SMW_CONFIG_MAC_ALGO_ID_INVALID;
		status = SMW_STATUS_OK;
	} else if (name < SMW_MAC_ALGO_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_CONFIG_MAC_ALGO_ID_OFFSET,
				  (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
