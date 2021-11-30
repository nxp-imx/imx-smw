// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

void hash_print_params(void *params)
{
	struct hash_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "    algo_bitmap: %.8lX\n",
		       p->algo_bitmap);
}
