// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "compiler.h"

#include "debug.h"
#include "devmgr.h"
#include "utils.h"

#include "common.h"

struct ele_get_info_head {
	uint8_t cmd;
	uint8_t version;
	uint16_t length;
	uint16_t soc_id;
	uint16_t soc_rev;
	uint16_t lifecycle;
	uint8_t ssm_state;
	uint8_t reserved;
	uint32_t uid[ELE_NB_UID_WORD];
};

static int get_uid(struct subsystem_context *ele_ctx, unsigned char *uid,
		   unsigned int *uid_length)
{
	int status = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	if (uid && *uid_length < info->uid_length)
		status = SMW_STATUS_OUTPUT_TOO_SHORT;

	*uid_length = info->uid_length;

	if (uid && status == SMW_STATUS_OK)
		SMW_UTILS_MEMCPY(uid, info->uid, info->uid_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int device_info_operation(struct hdl *hdl,
				 op_dev_getinfo_args_t *op_args)
{
	int status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_dev_getinfo(hdl->session, op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_dev_getinfo returned %d\n", err);

	status = ele_convert_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Check if all buffers allocated by the ELE Library are valid */
	if (!op_args->uid || !op_args->uid_sz || !op_args->sha_rom_patch ||
	    !op_args->rom_patch_sha_sz || !op_args->sha_fw ||
	    !op_args->sha_fw_sz)
		status = SMW_STATUS_SUBSYSTEM_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

static void free_device_info_operation(op_dev_getinfo_args_t *op_args)
{
	if (op_args->uid)
		SMW_UTILS_FREE(op_args->uid);
	if (op_args->sha_rom_patch)
		SMW_UTILS_FREE(op_args->sha_rom_patch);
	if (op_args->sha_fw)
		SMW_UTILS_FREE(op_args->sha_fw);
	if (op_args->oem_srkh)
		SMW_UTILS_FREE(op_args->oem_srkh);
}

static int device_uuid(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OK;

	unsigned char *uuid = NULL;
	unsigned int uuid_length = 0;
	unsigned char *certificate = NULL;
	unsigned int certificate_length = 0;
	unsigned int uid_length = 0;
	unsigned int *device_uid = NULL;
	int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	uuid = smw_devmgr_get_uuid_data(args);
	uuid_length = smw_devmgr_get_uuid_length(args);

	certificate = smw_devmgr_get_certificate_data(args);
	certificate_length = smw_devmgr_get_certificate_length(args);

	if (!certificate) {
		status = get_uid(ele_ctx, NULL, &uid_length);
		if (status != SMW_STATUS_OK)
			goto end;
	} else if (certificate_length >= sizeof(struct ele_get_info_head)) {
		device_uid = ((struct ele_get_info_head *)certificate)->uid;
		uid_length = ELE_UID_SIZE;
	} else {
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		smw_devmgr_set_uuid_length(args, ELE_UID_SIZE);
		goto end;
	}

	if (!uuid || uuid_length < uid_length) {
		smw_devmgr_set_uuid_length(args, uid_length);

		if (uuid && uuid_length < uid_length)
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
		else
			status = SMW_STATUS_OK;

		goto end;
	}

	if (!certificate) {
		status = get_uid(ele_ctx, uuid, &uid_length);
		if (status != SMW_STATUS_OK)
			goto end;
	} else {
		for (; i < ELE_NB_UID_WORD; i++, uuid += sizeof(*device_uid))
			SMW_UTILS_MEMCPY(uuid, &device_uid[i],
					 sizeof(*device_uid));
	}

	smw_devmgr_set_uuid_length(args, uid_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ele_get_device_info(struct subsystem_context *ele_ctx)
{
	int status = SMW_STATUS_OK;
	int status_mutex = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;
	uint8_t *uid = NULL;

	op_dev_getinfo_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(info->mutex)) {
		status_mutex = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	if (info->valid)
		goto end;

	status = device_info_operation(&ele_ctx->hdl, &op_args);
	if (status != SMW_STATUS_OK)
		goto end;

	uid = SMW_UTILS_MALLOC(op_args.uid_sz);
	if (!uid) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	SMW_DBG_ASSERT(!info->uid);

	info->uid = uid;
	info->uid_length = op_args.uid_sz;

	SMW_UTILS_MEMCPY(uid, op_args.uid, op_args.uid_sz);

	info->soc_id = op_args.soc_id;
	info->soc_rev = op_args.soc_rev;
	if (info->soc_id == SOC_IMX93 && info->soc_rev == SOC_REV_A1)
		info->attest_api_ver = HSM_API_VERSION_2;
	else
		info->attest_api_ver = HSM_API_VERSION_1;

	info->lifecycle = hsm_get_lc_from_lmda(op_args.lmda_val);

	info->valid = true;

end:
	if (status_mutex == SMW_STATUS_OK)
		if (smw_utils_mutex_unlock(info->mutex))
			status_mutex = SMW_STATUS_MUTEX_UNLOCK_FAILURE;

	if (status == SMW_STATUS_OK)
		status = status_mutex;

	/* Free all buffers allocated by the ELE Library */
	free_device_info_operation(&op_args);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_device_info_handle(struct subsystem_context *ele_ctx,
			    enum operation_id operation_id, void *args,
			    int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_DEVICE_GET_UUID:
		*status = device_uuid(ele_ctx, args);
		break;

	default:
		return false;
	}

	return true;
}
