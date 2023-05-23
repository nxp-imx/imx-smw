// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_device.h"

#include "subsystems.h"

#include "config.h"
#include "devmgr.h"
#include "debug.h"
#include "exec.h"

unsigned char *smw_devmgr_get_challenge_data(struct smw_devmgr_args *args)
{
	unsigned char *buffer = NULL;

	if (args->op == SMW_OP_DEVMGR_ATTESTATION && args->pub.attestation)
		buffer = args->pub.attestation->challenge;

	return buffer;
}

unsigned int smw_devmgr_get_challenge_length(struct smw_devmgr_args *args)
{
	unsigned int length = 0;

	if (args->op == SMW_OP_DEVMGR_ATTESTATION && args->pub.attestation)
		length = args->pub.attestation->challenge_length;

	return length;
}

void smw_devmgr_set_certificate_length(struct smw_devmgr_args *args,
				       unsigned int length)
{
	if (args->op == SMW_OP_DEVMGR_ATTESTATION && args->pub.attestation)
		args->pub.attestation->certificate_length = length;
}

enum smw_status_code
smw_device_attestation(struct smw_device_attestation_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_args attest_args = { 0 };
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

	attest_args.op = SMW_OP_DEVMGR_ATTESTATION;
	attest_args.pub.attestation = args;

	status = smw_utils_execute_operation(OPERATION_ID_DEVICE_ATTESTATION,
					     &attest_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
