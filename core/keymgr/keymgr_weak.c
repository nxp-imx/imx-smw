// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"
#include "smw_keymgr.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"

__attribute__((weak)) int smw_generate_key(struct smw_generate_key_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_derive_key(struct smw_derive_key_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_update_key(struct smw_update_key_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_import_key(struct smw_import_key_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_export_key(struct smw_export_key_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_delete_key(struct smw_delete_key_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
