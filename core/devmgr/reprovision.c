// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "smw_device.h"

#include "config.h"
#include "debug.h"
#include "devmgr.h"
#include "exec.h"
#include "subsystems.h"

unsigned char *smw_devmgr_get_reprovision_data(struct smw_devmgr_args *args)
{
	unsigned char *buffer = NULL;

	if ((args->op == SMW_OP_DEVMGR_REPROVISION_PREP ||
	     args->op == SMW_OP_DEVMGR_REPROVISION) &&
	    args->pub.reprovision)
		buffer = args->pub.reprovision->data;

	return buffer;
}

unsigned int smw_devmgr_get_reprovision_length(struct smw_devmgr_args *args)
{
	unsigned int length = 0;

	if ((args->op == SMW_OP_DEVMGR_REPROVISION_PREP ||
	     args->op == SMW_OP_DEVMGR_REPROVISION) &&
	    args->pub.reprovision)
		length = args->pub.reprovision->data_length;

	return length;
}

void smw_devmgr_set_reprovision_length(struct smw_devmgr_args *args,
				       unsigned int length)
{
	if ((args->op == SMW_OP_DEVMGR_REPROVISION_PREP ||
	     args->op == SMW_OP_DEVMGR_REPROVISION) &&
	    args->pub.reprovision)
		args->pub.reprovision->data_length = length;
}

enum smw_status_code
smw_device_reprovision_prepare(struct smw_device_reprovision_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_args repro_args = { 0 };
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

	repro_args.op = SMW_OP_DEVMGR_REPROVISION_PREP;
	repro_args.pub.reprovision = args;

	status = smw_utils_execute_operation(OPERATION_ID_DEVICE_REPROVISION,
					     &repro_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_device_reprovision(struct smw_device_reprovision_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_args repro_args = { 0 };
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

	repro_args.op = SMW_OP_DEVMGR_REPROVISION;
	repro_args.pub.reprovision = args;

	status = smw_utils_execute_operation(OPERATION_ID_DEVICE_REPROVISION,
					     &repro_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
