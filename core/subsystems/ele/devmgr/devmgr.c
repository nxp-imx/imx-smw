// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include "compiler.h"

#include "debug.h"
#include "devmgr.h"
#include "utils.h"

#include "local.h"

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

static void features_per_soc(struct ele_info *info)
{
	SMW_DBG_PRINTF(DEBUG, "soc_id = 0x%x\n", info->soc_id);

	switch (info->soc_id) {
	case SOC_IMX8ULP:
		break;

	case SOC_IMX943:
		info->aead_multipart = true;
		info->sign_verif_opaque_key = true;

		break;

	case SOC_IMX91:
	case SOC_IMX93:
		info->edwards_be = true;
		break;

	default:
		/* All others SOC (95, 952, ...)*/
		info->sign_verif_opaque_key = true;
		info->aead_multipart = true;
		break;
	}
}

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
	if (op_args->oem_pqc_srkh)
		SMW_UTILS_FREE(op_args->oem_pqc_srkh);
}

static int ele_device_uuid(struct subsystem_context *ele_ctx, void *args)
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
	size_t i = 0;

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

	info->attest_api_ver = hsm_get_dev_attest_api_ver();

	info->lifecycle = hsm_get_lc_from_lmda(op_args.lmda_val);

	/* Verify if the OEM SRKH is fused */
	if (op_args.oem_srkh && op_args.oem_srkh_sz) {
		for (; i < op_args.oem_srkh_sz; i++) {
			if (op_args.oem_srkh[i]) {
				info->srkh_fused = true;
				break;
			}
		}
	}

	/* Set the specific SOC features */
	features_per_soc(info);

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

int ele_is_oem_srkh_fused(struct subsystem_context *ele_ctx, bool *fused)
{
	int status = SMW_STATUS_OK;

	struct ele_info *info = &ele_ctx->info;

	status = ele_get_device_info(ele_ctx);
	if (status != SMW_STATUS_OK)
		goto end;

	*fused = info->srkh_fused;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak bool ele_device_lifecycle_handle(struct subsystem_context *ele_ctx,
					enum operation_id operation_id,
					void *args, int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_device_reprovisioning_handle(struct subsystem_context *ele_ctx,
					     enum operation_id operation_id,
					     void *args, int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

bool ele_device_manager_handle(struct subsystem_context *ele_ctx,
			       enum operation_id operation_id, void *args,
			       int *status)
{
	bool handled = false;

	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_DEVICE_GET_UUID:
		*status = ele_device_uuid(ele_ctx, args);
		handled = true;
		break;

	default:
		if (ele_device_attest_handle(ele_ctx, operation_id, args,
					     status))
			handled = true;
		else if (ele_device_lifecycle_handle(ele_ctx, operation_id,
						     args, status))
			handled = true;
		else if (ele_storage_handle(ele_ctx, operation_id, args,
					    status))
			handled = true;
		else if (ele_device_reprovisioning_handle(ele_ctx, operation_id,
							  args, status))
			handled = true;
	}

	return handled;
}
