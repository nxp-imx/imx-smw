// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2024 NXP
 */

#include "debug.h"

#include "common.h"

void sign_verify_print_params(void *params)
{
	struct sign_verify_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "\talgo_bitmap: %.8lX\n"
		       "\tsign_type_bitmap: %.8lX\n",
		       p->algo_bitmap, p->sign_type_bitmap);

	print_key_params(&p->key);
}
