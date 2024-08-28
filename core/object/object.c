// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "debug.h"
#include "object_db.h"
#include "osal.h"

enum smw_status_code
smw_update_object_db(struct smw_object_descriptor *descriptor)
{
	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (descriptor->id == INVALID_OBJ_ID)
		return SMW_STATUS_UNKNOWN_ID;

	return smw_object_db_update(descriptor->id, descriptor->attributes,
				    descriptor);
}

enum smw_status_code
smw_find_object_db(struct smw_object_descriptor *descriptor)
{
	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (descriptor->id == INVALID_OBJ_ID)
		return SMW_STATUS_UNKNOWN_ID;

	return smw_object_db_get_info(descriptor->id, descriptor->attributes,
				      descriptor);
}

enum smw_status_code
smw_find_object_db_init(void **ctx, smw_attr_attributes_t attributes,
			struct smw_object_descriptor *descriptor)
{
	enum smw_status_code status = SMW_STATUS_OBJ_DB_FIND;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->find_obj_init)
		return SMW_STATUS_OPS_INVALID;

	obj.attributes = attributes;
	obj.descriptor = descriptor;

	if (!ops->find_obj_init(ctx, &obj))
		status = SMW_STATUS_OK;

	return status;
}

enum smw_status_code
smw_find_object_db_next(void *ctx, struct smw_object_descriptor *descriptor)
{
	enum smw_status_code status = SMW_STATUS_OBJ_DB_FIND;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->find_obj_next)
		return SMW_STATUS_OPS_INVALID;

	obj.descriptor = descriptor;

	if (!ops->find_obj_next(ctx, &obj))
		status = SMW_STATUS_OK;
	else if (obj.id == INVALID_OBJ_ID)
		status = SMW_STATUS_UNKNOWN_ID;

	return status;
}

enum smw_status_code smw_find_object_db_final(void *ctx)
{
	enum smw_status_code status = SMW_STATUS_OBJ_DB_FIND;
	struct smw_ops *ops = get_smw_ops();

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ops || !ops->find_obj_final)
		return SMW_STATUS_OPS_INVALID;

	if (!ops->find_obj_final(ctx))
		status = SMW_STATUS_OK;

	return status;
}
