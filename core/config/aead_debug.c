// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "debug.h"

#include "common.h"

void aead_common_print_params(void *params)
{
	struct aead_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "\tmode_bitmap: 0x%.8lX\n"
		       "\top_bitmap: 0x%.8lX\n",
		       p->mode_bitmap, p->op_bitmap);

	print_key_params(&p->key);
}
