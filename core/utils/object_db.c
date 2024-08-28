// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "debug.h"
#include "global.h"
#include "object_db.h"

static void prepare_osal_obj(unsigned int id, smw_attr_attributes_t attributes,
			     struct smw_object_descriptor *descriptor,
			     struct osal_obj *obj)
{
	if (descriptor)
		descriptor->id = id;
	obj->id = id;
	obj->attributes = attributes;
	obj->descriptor = descriptor;
}

int smw_object_db_create(unsigned int *id, smw_attr_attributes_t attributes,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_CREATE;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!id || !descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->add_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(*id, attributes, descriptor, &obj);

	if (!ops->add_obj_info(&obj) && obj.id != INVALID_OBJ_ID) {
		*id = obj.id;
		ret = SMW_STATUS_OK;
	}

	return ret;
}

int smw_object_db_update(unsigned int id, smw_attr_attributes_t attributes,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_UPDATE;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->update_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(id, attributes, descriptor, &obj);

	if (!ops->update_obj_info(&obj))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_delete(unsigned int id, smw_attr_attributes_t attributes)
{
	int ret = SMW_STATUS_OBJ_DB_DELETE;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ops || !ops->delete_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(id, attributes, NULL, &obj);

	if (!ops->delete_obj_info(&obj))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_get_info(unsigned int id, smw_attr_attributes_t attributes,
			   struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_GET_INFO;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->get_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(id, attributes, descriptor, &obj);

	if (!ops->get_obj_info(&obj))
		ret = SMW_STATUS_OK;
	else if (obj.id == INVALID_OBJ_ID)
		ret = SMW_STATUS_UNKNOWN_ID;

	return ret;
}
