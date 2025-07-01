// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "debug.h"
#include "object_db.h"
#include "osal.h"

static int find_data_in_subsystem(struct smw_object_descriptor *obj)
{
	struct smw_data_info_args data_info = { 0 };
	struct smw_data_descriptor data_desc = { 0 };

	data_info.data_descriptor = &data_desc;
	data_desc.identifier = obj->id;

	return smw_get_data_info(&data_info);
}

static int find_key_in_subsystem(struct smw_object_descriptor *obj)
{
	struct smw_get_key_attributes_args key_attrs = { 0 };
	struct smw_key_descriptor key_desc = { 0 };

	key_attrs.key_descriptor = &key_desc;
	key_desc.id = obj->id;

	return smw_get_key_attributes(&key_attrs);
}

static int find_object_in_subsystem(struct smw_object_descriptor *obj)
{
	int status = SMW_STATUS_OK;

	switch (obj->type) {
	case SMW_OBJECT_TYPE_NAME_DATA:
		status = find_data_in_subsystem(obj);
		break;

	case SMW_OBJECT_TYPE_NAME_SECRET_KEY:
	case SMW_OBJECT_TYPE_NAME_PUBLIC_KEY:
	case SMW_OBJECT_TYPE_NAME_KEY_PAIR:
		status = find_key_in_subsystem(obj);
		break;

	default:
		/* Unknown object type, hence try to get key then data */
		obj->type = SMW_OBJECT_TYPE_NAME_KEY_PAIR;
		status = find_key_in_subsystem(obj);
		if (status == SMW_STATUS_OK)
			break;

		obj->type = SMW_OBJECT_TYPE_NAME_DATA;
		status = find_data_in_subsystem(obj);
		break;
	}

	return status;
}

enum smw_status_code
smw_update_object_db(struct smw_object_descriptor *descriptor)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_API_CALL;

	if (!descriptor)
		goto end;

	if (descriptor->id == INVALID_OBJ_ID) {
		status = SMW_STATUS_UNKNOWN_ID;
		goto end;
	}

	/* Object identifier in the subsystem is unknown here. */
	status = smw_object_db_update(INVALID_OBJ_ID, descriptor);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_find_object_db(struct smw_find_object_db_args *args)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_object_descriptor *obj_desc = NULL;
	struct smw_object_descriptor cpy_obj_desc = { 0 };
	unsigned int s_id = INVALID_OBJ_ID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->object_descriptor)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	obj_desc = args->object_descriptor;

	if (obj_desc->id == INVALID_OBJ_ID) {
		status = SMW_STATUS_UNKNOWN_ID;
		goto end;
	}

	/*
	 * Create a copy of the object descriptor in case object not present
	 * in the database. The database get information can overwrite user
	 * input data.
	 */
	cpy_obj_desc = *obj_desc;

	status = smw_object_db_get_info(&s_id, obj_desc);

	if (status == SMW_STATUS_UNKNOWN_ID) {
		/*
		 * Object ID is not present in the database, query the
		 * subsystem.
		 */
		status = find_object_in_subsystem(&cpy_obj_desc);
		if (status == SMW_STATUS_OK) {
			*obj_desc = cpy_obj_desc;
			status = smw_object_db_get_info(&s_id, obj_desc);
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_find_object_db_init(struct smw_find_object_db_args *args)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_ops *ops = get_smw_ops();
	struct smw_osal_object obj = { 0 };
	unsigned int s_id = INVALID_OBJ_ID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->object_descriptor)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	if (!ops || !ops->find_obj_init) {
		status = SMW_STATUS_OPS_INVALID;
		goto end;
	}

	smw_object_db_prepare(s_id, args->object_descriptor, &obj);

	if (!ops->find_obj_init(&args->ctx, &obj))
		status = SMW_STATUS_OK;
	else
		status = SMW_STATUS_OBJ_DB_FIND;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_find_object_db_next(struct smw_find_object_db_args *args)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_ops *ops = get_smw_ops();
	struct smw_osal_object obj = { 0 };
	unsigned int s_id = INVALID_OBJ_ID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->object_descriptor)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	if (!ops || !ops->find_obj_next) {
		status = SMW_STATUS_OPS_INVALID;
		goto end;
	}

	smw_object_db_prepare(s_id, args->object_descriptor, &obj);

	if (!ops->find_obj_next(args->ctx, &obj))
		status = SMW_STATUS_OK;
	else if (args->object_descriptor->id == INVALID_OBJ_ID)
		status = SMW_STATUS_UNKNOWN_ID;
	else
		status = SMW_STATUS_OBJ_DB_FIND;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_find_object_db_final(struct smw_find_object_db_args *args)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_ops *ops = get_smw_ops();

	SMW_DBG_TRACE_API_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	if (!ops || !ops->find_obj_final) {
		status = SMW_STATUS_OPS_INVALID;
		goto end;
	}

	if (!ops->find_obj_final(args->ctx))
		status = SMW_STATUS_OK;
	else
		status = SMW_STATUS_OBJ_DB_FIND;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
