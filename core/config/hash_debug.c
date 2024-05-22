// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2024 NXP
 */

#include "debug.h"

#include "common.h"

void hash_print_params(void *params)
{
	struct hash_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "\talgo_bitmap: 0x%.8lX\n",
		       p->algo_bitmap);
}
