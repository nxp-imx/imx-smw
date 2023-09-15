// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_device.h"

#include "compiler.h"
#include "debug.h"

__weak enum smw_status_code
smw_device_get_lifecycle(struct smw_device_lifecycle_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_device_set_lifecycle(struct smw_device_lifecycle_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
