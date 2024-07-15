// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022, 2024 NXP
 */

#include "smw/names.h"

#include "local.h"

__export smw_subsystem_t smw_osal_latest_subsystem_name(void)
{
	struct osal_ctx *ctx = get_osal_ctx();

	TRACE_FUNCTION_CALL;

	if (!ctx)
		return SMW_SUBSYSTEM_NAME_NONE;

	return ctx->active_subsystem_name;
}
