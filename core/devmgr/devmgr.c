// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024, 2026 NXP
 */

#include "smw_device.h"

#include "subsystems.h"

#include "config.h"
#include "debug.h"
#include "devmgr.h"
#include "exec.h"
#include "lifecycle.h"

unsigned char *smw_devmgr_get_certificate_data(struct smw_devmgr_args *args)
{
	unsigned char *buffer = NULL;

	switch (args->op) {
	case SMW_OP_DEVMGR_ATTESTATION:
		if (args->pub.attestation)
			buffer = args->pub.attestation->certificate;
		break;

	case SMW_OP_DEVMGR_UUID:
		if (args->pub.uuid)
			buffer = args->pub.uuid->certificate;
		break;

	default:
		break;
	}

	return buffer;
}

unsigned int smw_devmgr_get_certificate_length(struct smw_devmgr_args *args)
{
	unsigned int length = 0;

	switch (args->op) {
	case SMW_OP_DEVMGR_ATTESTATION:
		if (args->pub.attestation)
			length = args->pub.attestation->certificate_length;
		break;

	case SMW_OP_DEVMGR_UUID:
		if (args->pub.uuid)
			length = args->pub.uuid->certificate_length;
		break;

	default:
		break;
	}

	return length;
}

unsigned char *smw_devmgr_get_uuid_data(struct smw_devmgr_args *args)
{
	unsigned char *buffer = NULL;

	if (args->op == SMW_OP_DEVMGR_UUID && args->pub.uuid)
		buffer = args->pub.uuid->uuid;

	return buffer;
}

unsigned int smw_devmgr_get_uuid_length(struct smw_devmgr_args *args)
{
	unsigned int length = 0;

	if (args->op == SMW_OP_DEVMGR_UUID && args->pub.uuid)
		length = args->pub.uuid->uuid_length;

	return length;
}

void smw_devmgr_set_uuid_length(struct smw_devmgr_args *args,
				unsigned int length)
{
	if (args->op == SMW_OP_DEVMGR_UUID && args->pub.uuid)
		args->pub.uuid->uuid_length = length;
}

void smw_devmgr_set_device_soc(struct smw_devmgr_args *args,
			       smw_soc_id_t soc_id, smw_soc_revision_t soc_rev)
{
	if (args->op == SMW_OP_DEVMGR_GET_INFO && args->pub.info) {
		args->pub.info->soc_id = soc_id;
		args->pub.info->soc_rev = soc_rev;
	}
}

void smw_devmgr_set_device_lifecycle(struct smw_devmgr_args *args,
				     enum smw_lifecycle_id id)
{
	if (args->op == SMW_OP_DEVMGR_GET_INFO && args->pub.info)
		smw_lifecycle_set_name(id, &args->pub.info->lifecycle);
}

void smw_devmgr_set_device_srkh(struct smw_devmgr_args *args, bool srkh_fused)
{
	if (args->op == SMW_OP_DEVMGR_GET_INFO && args->pub.info)
		args->pub.info->srkh_fused = srkh_fused;
}

enum smw_status_code smw_device_get_uuid(struct smw_device_uuid_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_args uuid_args = { 0 };
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

	uuid_args.op = SMW_OP_DEVMGR_UUID;
	uuid_args.pub.uuid = args;

	status = smw_utils_execute_implicit(OPERATION_ID_DEVICE_GET_UUID,
					    &uuid_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_device_get_info(struct smw_device_info_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_devmgr_args info_args = { 0 };
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

	info_args.op = SMW_OP_DEVMGR_GET_INFO;
	info_args.pub.info = args;

	status = smw_utils_execute_implicit(OPERATION_ID_DEVICE_GET_INFO,
					    &info_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
