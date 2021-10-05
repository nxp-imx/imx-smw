// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

void print_key_operation_params(void *params)
{
	struct key_operation_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "%s params:\n"
		       "    op_bitmap: %.8lX\n",
		       smw_config_get_operation_name(p->operation_id),
		       p->op_bitmap);

	print_key_params(&p->key);
}
