// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw/names.h"
#include "smw_device.h"

#include "subsystems.h"

#include "config.h"
#include "lifecycle.h"
#include "devmgr.h"
#include "debug.h"
#include "exec.h"
#include "utils.h"

/*
 * Ordering must be the same for internal values and public values.
 * This way the offset between the internal values and the public values
 * can be used for conversion, and no conversion table is required.
 *
 * The offset between the internal values and the public values is
 * given by the first public value.
 */

#define SMW_LIFECYCLE_ID_OFFSET                                                \
	(SMW_LIFECYCLE_NAME_CURRENT - SMW_LIFECYCLE_ID_CURRENT)

static int get_lifecycle_id(smw_lifecycle_t name, enum smw_lifecycle_id *id)
{
	int status = SMW_STATUS_INVALID_LIFECYCLE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (name != SMW_LIFECYCLE_NAME_NONE && name < SMW_LIFECYCLE_NAME_NB) {
		if (!SUB_OVERFLOW(name, SMW_LIFECYCLE_ID_OFFSET, (int *)id))
			status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_lifecycle_name(enum smw_lifecycle_id id, smw_lifecycle_t *name)
{
	int status = SMW_STATUS_INVALID_LIFECYCLE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (id < SMW_LIFECYCLE_ID_NB && id != SMW_LIFECYCLE_ID_INVALID) {
		if (!ADD_OVERFLOW(id, SMW_LIFECYCLE_ID_OFFSET, (int *)name))
			status = SMW_STATUS_OK;
	}

	return status;
}

enum smw_status_code
smw_device_set_lifecycle(struct smw_device_lifecycle_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_lifecycle_args lc_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_lifecycle_id(args->lifecycle_name, &lc_args.lifecycle_id);
	if (status != SMW_STATUS_OK)
		goto end;

	lc_args.op = SMW_OP_DEVMGR_SET_LIFECYCLE;

	status = smw_utils_execute_operation(OPERATION_ID_DEVICE_LIFECYCLE,
					     &lc_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_device_get_lifecycle(struct smw_device_lifecycle_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_lifecycle_args lc_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	lc_args.op = SMW_OP_DEVMGR_GET_LIFECYCLE;

	status = smw_utils_execute_operation(OPERATION_ID_DEVICE_LIFECYCLE,
					     &lc_args, subsystem_id);
	if (status == SMW_STATUS_OK)
		status = get_lifecycle_name(lc_args.lifecycle_id,
					    &args->lifecycle_name);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
