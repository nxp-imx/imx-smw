// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "osal.h"

__export const char *smw_read_latest_subsystem_name(void)
{
	TRACE_FUNCTION_CALL;

	return active_subsystem_name;
}
