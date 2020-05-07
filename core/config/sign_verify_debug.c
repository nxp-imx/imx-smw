// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "crypto.h"

#include "common.h"

void sign_verify_print_params(void *params)
{
	struct sign_verify_params *p = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!p)
		return;

	SMW_DBG_PRINTF(DEBUG,
		       "%s params:\n"
		       "    algo_bitmap: %.8lX\n"
		       "    key_type_bitmap: %.8lX\n"
		       "    key_size_min: %u\n"
		       "    key_size_max: %u\n",
		       smw_config_get_operation_name(p->operation_id),
		       p->algo_bitmap, p->key_type_bitmap, p->key_size_min,
		       p->key_size_max);
}
