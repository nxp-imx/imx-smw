// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "debug.h"
#include "global.h"
#include "object_db.h"

void smw_object_db_prep_desc(unsigned int id,
			     struct smw_object_descriptor *descriptor)
{
	smw_attr_attributes_t persistence = 0;

	descriptor->id = id;

	switch (descriptor->type) {
	case SMW_OBJECT_TYPE_NAME_DATA:
		persistence = descriptor->data.attributes.attributes;
		break;

	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		persistence = descriptor->key.attributes.attributes;
		break;

	default:
		persistence = descriptor->persistency;
		break;
	}

	persistence = SMW_ATTR_GET_PERSISTENCE(persistence);
	descriptor->persistency = SMW_ATTR_SET_PERSISTENCE(0, persistence);
}

int smw_object_db_create(unsigned int *id,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_CREATE;
	struct smw_ops *ops = get_smw_ops();

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!id || !descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->add_obj_info)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prep_desc(*id, descriptor);

	if (!ops->add_obj_info(descriptor) &&
	    descriptor->id != INVALID_OBJ_ID) {
		*id = descriptor->id;
		ret = SMW_STATUS_OK;
	}

	return ret;
}

int smw_object_db_update(unsigned int id,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_UPDATE;
	struct smw_ops *ops = get_smw_ops();

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->update_obj_info)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prep_desc(id, descriptor);

	if (!ops->update_obj_info(descriptor))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_delete(unsigned int id,
			 struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_DELETE;
	struct smw_ops *ops = get_smw_ops();

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ops || !ops->delete_obj_info || !descriptor)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prep_desc(id, descriptor);

	if (!ops->delete_obj_info(descriptor))
		ret = SMW_STATUS_OK;

	return ret;
}

int smw_object_db_get_info(unsigned int id,
			   struct smw_object_descriptor *descriptor)
{
	int ret = SMW_STATUS_OBJ_DB_GET_INFO;
	struct smw_ops *ops = get_smw_ops();

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		return SMW_STATUS_INVALID_PARAM;

	if (!ops || !ops->get_obj_info)
		return SMW_STATUS_OPS_INVALID;

	smw_object_db_prep_desc(id, descriptor);

	if (!ops->get_obj_info(descriptor))
		ret = SMW_STATUS_OK;
	else if (descriptor->id == INVALID_OBJ_ID)
		ret = SMW_STATUS_UNKNOWN_ID;

	return ret;
}
