// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "debug.h"

#include "common.h"

void mac_print_params(void *params)
{
	struct mac_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "    algo_bitmap: 0x%.8lX\n"
		       "    hash_bitmap: 0x%.8lX\n",
		       p->algo_bitmap, p->hash_bitmap);

	print_key_params(&p->key);
}
