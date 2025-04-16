// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "debug.h"

#include "common.h"

void asymmetric_encryption_print_params(void *params)
{
	struct asymmetric_encryption_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "\talgo_bitmap: 0x%.8lX\n"
		       "\tmode_bitmap: 0x%.8lX\n"
		       "\thash_bitmap: 0x%.8lX\n",
		       p->algo_bitmap, p->mode_bitmap, p->hash_bitmap);
}
