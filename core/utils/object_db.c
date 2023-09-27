// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "global.h"
#include "object_db.h"

static void prepare_osal_obj(unsigned int id, int persistence,
			     union smw_object_db_info *info,
			     struct osal_obj *obj)
{
	obj->id = id;
	obj->persistence = persistence;
	obj->info = info;
	obj->info_size = sizeof(*info);

	/* If the object id is known, there is no object id range */
	if (obj->id == INVALID_OBJ_ID) {
		obj->range.min = 1;
		obj->range.max = UINT32_MAX;
	} else {
		obj->range.min = obj->id;
		obj->range.max = obj->id;
	}
}

int smw_object_db_create(unsigned int *id,
			 enum smw_object_persistence_id persistence_id,
			 union smw_object_db_info *info)
{
	int ret = SMW_STATUS_OBJ_DB_CREATE;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!id || !info)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->add_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(*id, persistence_id, info, &obj);

	if (!ops->add_obj_info(&obj) && obj.id != INVALID_OBJ_ID) {
		*id = obj.id;
		ret = SMW_STATUS_OK;
	}

	return ret;
}

int smw_object_db_update(unsigned int id,
			 enum smw_object_persistence_id persistence_id,
			 union smw_object_db_info *info)
{
	int ret = SMW_STATUS_OBJ_DB_UPDATE;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->update_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(id, persistence_id, info, &obj);

	if (!ops->update_obj_info(&obj))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_delete(unsigned int id,
			 enum smw_object_persistence_id persistence_id)

{
	int ret = SMW_STATUS_OBJ_DB_DELETE;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ops || !ops->delete_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(id, persistence_id, NULL, &obj);

	if (!ops->delete_obj_info(&obj))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_get_info(unsigned int id,
			   enum smw_object_persistence_id persistence_id,
			   union smw_object_db_info *info)
{
	int ret = SMW_STATUS_OBJ_DB_GET_INFO;
	struct smw_ops *ops = get_smw_ops();
	struct osal_obj obj = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->get_obj_info)
		return SMW_STATUS_OPS_INVALID;

	prepare_osal_obj(id, persistence_id, info, &obj);

	if (!ops->get_obj_info(&obj))
		ret = SMW_STATUS_OK;
	else if (obj.id == INVALID_OBJ_ID)
		ret = SMW_STATUS_UNKNOWN_ID;

	return ret;
}
