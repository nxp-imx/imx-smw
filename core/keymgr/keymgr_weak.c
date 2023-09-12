// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "smw_status.h"
#include "smw_keymgr.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"

__weak enum smw_status_code smw_generate_key(struct smw_generate_key_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_derive_key(struct smw_derive_key_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_update_key(struct smw_update_key_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_import_key(struct smw_import_key_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_export_key(struct smw_export_key_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_delete_key(struct smw_delete_key_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor)
{
	(void)descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_get_key_type_name(struct smw_key_descriptor *descriptor)
{
	(void)descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_get_security_size(struct smw_key_descriptor *descriptor)
{
	(void)descriptor;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_get_key_attributes(struct smw_get_key_attributes_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
