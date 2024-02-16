// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2024 NXP
 */

#include "debug.h"

#include "common.h"

void print_key_operation_params(void *params)
{
	struct key_operation_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "\top_bitmap: %.8lX\n",
		       p->op_bitmap);

	print_key_params(&p->key);
}
