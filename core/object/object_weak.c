// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "compiler.h"
#include "debug.h"

__weak enum smw_status_code
smw_find_object_db(struct smw_object_descriptor *descriptor)
{
	(void)descriptor;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_find_object_db_init(void **ctx, smw_attr_attributes_t attributes,
			struct smw_object_descriptor *descriptor)
{
	(void)ctx;
	(void)descriptor;
	(void)attributes;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_find_object_db_next(void *ctx, struct smw_object_descriptor *descriptor)
{
	(void)ctx;
	(void)descriptor;

	SMW_DBG_TRACE_API_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_find_object_db_final(void *ctx)
{
	(void)ctx;

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
