// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "smw_status.h"
#include "smw/object.h"

#include "debug.h"
#include "object_db.h"
#include "osal.h"

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

	status = smw_object_db_get_info(&s_id, obj_desc);

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
