// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

void hmac_print_params(void *params)
{
	struct hmac_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "HMAC params:\n"
		       "    algo_bitmap: %.8lX\n"
		       "    key_type_bitmap: %.8lX\n"
		       "    key_size_min: %u\n"
		       "    key_size_max: %u\n",
		       p->algo_bitmap, p->key_type_bitmap, p->key_size_min,
		       p->key_size_max);
}
