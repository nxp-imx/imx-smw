// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2024 NXP
 */

#include "debug.h"

#include "common.h"

void rng_print_params(void *params)
{
	struct rng_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "    range_min: %u\n"
		       "    range_max: %u\n",
		       p->range.min, p->range.max);
}
