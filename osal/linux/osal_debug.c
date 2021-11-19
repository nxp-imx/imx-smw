// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include "local.h"

__export const char *smw_osal_latest_subsystem_name(void)
{
	TRACE_FUNCTION_CALL;

	return osal_priv.active_subsystem_name;
}
