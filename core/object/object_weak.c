// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "compiler.h"
#include "debug.h"

__weak enum smw_status_code
smw_find_object_db(struct smw_find_object_db_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_find_object_db_init(struct smw_find_object_db_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_find_object_db_next(struct smw_find_object_db_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_find_object_db_final(struct smw_find_object_db_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_update_object_db(struct smw_object_descriptor *descriptor)
{
	(void)descriptor;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
