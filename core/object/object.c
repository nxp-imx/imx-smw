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

	status = smw_object_db_update(descriptor->id, descriptor);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_find_object_db(struct smw_find_object_db_args *args)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_object_descriptor *obj_desc = NULL;

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

	status = smw_object_db_get_info(obj_desc->id, obj_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_find_object_db_init(struct smw_find_object_db_args *args)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_ops *ops = get_smw_ops();
	struct smw_object_descriptor *obj_desc = NULL;

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

	obj_desc = args->object_descriptor;

	smw_object_db_prep_desc(obj_desc->id, obj_desc);

	if (!ops->find_obj_init(&args->ctx, obj_desc))
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
	struct smw_object_descriptor *obj_desc = NULL;

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

	obj_desc = args->object_descriptor;

	smw_object_db_prep_desc(obj_desc->id, obj_desc);

	if (!ops->find_obj_next(args->ctx, obj_desc))
		status = SMW_STATUS_OK;
	else if (obj_desc->id == INVALID_OBJ_ID)
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
