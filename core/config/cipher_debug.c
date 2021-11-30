// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

void cipher_common_print_params(void *params)
{
	struct cipher_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "Params:\n"
		       "    mode_bitmap: %.8lX\n"
		       "    op_bitmap: %.8lX\n",
		       p->mode_bitmap, p->op_bitmap);

	print_key_params(&p->key);
}
