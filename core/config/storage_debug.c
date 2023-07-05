// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"

#include "common.h"

void storage_store_print_params(void *params)
{
	struct storage_store_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "    mode_bitmap: %.8lX\n"
		       "    algo_bitmap: %.8lX\n"
		       "    hash_bitmap: %.8lX\n",
		       p->mode_bitmap, p->algo_bitmap, p->hash_bitmap);

	print_key_params(&p->key);
}
