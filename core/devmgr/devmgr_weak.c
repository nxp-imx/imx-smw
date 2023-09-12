// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_device.h"

#include "compiler.h"
#include "debug.h"
#include "devmgr.h"

__weak unsigned char *
smw_devmgr_get_challenge_data(struct smw_devmgr_args *args)
{
	(void)args;

	return NULL;
}

__weak unsigned int
smw_devmgr_get_challenge_length(struct smw_devmgr_args *args)
{
	(void)args;

	return 0;
}

__weak void smw_devmgr_set_certificate_length(struct smw_devmgr_args *args,
					      unsigned int length)
{
	(void)args;
	(void)length;
}

__weak enum smw_status_code
smw_device_attestation(struct smw_device_attestation_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code
smw_device_get_uuid(struct smw_device_uuid_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
