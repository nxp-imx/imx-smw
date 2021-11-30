// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "local.h"

__export const char *smw_osal_latest_subsystem_name(void)
{
	TRACE_FUNCTION_CALL;

	return active_subsystem_name;
}
