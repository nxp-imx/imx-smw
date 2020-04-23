// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "hsm_api.h"

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"

int alloc_out_key(uint8_t **out_key, uint16_t *out_size,
		  unsigned int security_size)
{
	int status = SMW_STATUS_OK;

	if (SMW_DBG_LEVEL >= SMW_DBG_LEVEL_DEBUG) {
		*out_size = security_size >> 2;
		*out_key = (uint8_t *)SMW_UTILS_MALLOC(*out_size);
		if (!*out_key)
			status = SMW_STATUS_ALLOC_FAILURE;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void print_out_key(uint8_t *out_key, uint16_t out_size)
{
	SMW_DBG_PRINTF(DEBUG, "Out key:\n");
	SMW_DBG_HEX_DUMP(DEBUG, out_key, out_size, 4);
}

void free_out_key(uint8_t *out_key)
{
	if (out_key)
		SMW_UTILS_FREE(out_key);
}
