// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_device.h"

#include "subsystems.h"

#include "config.h"
#include "constants.h"
#include "devmgr.h"
#include "debug.h"
#include "exec.h"
#include "tlv_strings.h"
#include "utils.h"

#define LIFECYCLE(_name)                                                       \
	{                                                                      \
		.lifecycle_str = LC_##_name##_STR,                             \
		.lifecycle = SMW_LIFECYCLE_##_name,                            \
	}

/**
 * struct - Lifecycle
 * @lifecycle_str: Lifecycle name used for TLV encoding.
 * @lifecycle: Lifecycle id.
 */
static const struct {
	const char *lifecycle_str;
	unsigned int lifecycle;
} lifecycle_info[] = { LIFECYCLE(OPEN), LIFECYCLE(CLOSED),
		       LIFECYCLE(CLOSED_LOCKED), LIFECYCLE(OEM_RETURN),
		       LIFECYCLE(NXP_RETURN) };

static int get_lifecycle(const char *name, unsigned int *id)
{
	int status = SMW_STATUS_INVALID_LIFECYCLE;
	unsigned int i = 0;

	if (!name)
		return status;

	for (; i < ARRAY_SIZE(lifecycle_info); i++) {
		if (!SMW_UTILS_STRCMP(name, lifecycle_info[i].lifecycle_str)) {
			*id = lifecycle_info[i].lifecycle;
			status = SMW_STATUS_OK;
			break;
		}
	}

	return status;
}

static int set_lifecycle(unsigned int id, const char **name)
{
	int status = SMW_STATUS_INVALID_LIFECYCLE;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(lifecycle_info); i++) {
		if (id == lifecycle_info[i].lifecycle) {
			*name = lifecycle_info[i].lifecycle_str;
			status = SMW_STATUS_OK;
			break;
		}
	}

	return status;
}

enum smw_status_code
smw_device_set_lifecycle(struct smw_device_lifecycle_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_lifecycle_args lc_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_INVALID_VERSION;
		goto end;
	}

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_lifecycle(args->lifecycle_name, &lc_args.lifecycle_id);
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

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_INVALID_VERSION;
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
		status = set_lifecycle(lc_args.lifecycle_id,
				       &args->lifecycle_name);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
