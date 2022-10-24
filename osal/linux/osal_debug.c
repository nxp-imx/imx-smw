// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "local.h"

__export const char *smw_osal_latest_subsystem_name(void)
{
	struct osal_ctx *ctx = get_osal_ctx();

	TRACE_FUNCTION_CALL;

	if (!ctx)
		return NULL;

	return ctx->active_subsystem_name;
}
