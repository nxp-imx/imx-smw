// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include "smw_storage.h"

#include "compiler.h"
#include "debug.h"

__weak enum smw_status_code smw_store_data(struct smw_store_data_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_retrieve_data(struct smw_retrieve_data_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_delete_data(struct smw_delete_data_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_get_data_info(struct smw_data_info_args *args)
{
	(void)args;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
