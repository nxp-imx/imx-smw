// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <time.h>

#include "compiler.h"
#include "debug.h"
#include "devmgr.h"
#include "utils.h"

#include "local.h"

struct __packed payload_reprovision {
	uint8_t flags;
	uint8_t target;
	uint16_t res;
	uint32_t monotonic_counter;
	uint32_t user_sab_id;
};

#define PAYLOAD_LENGTH sizeof(struct payload_reprovision)
#define COMMAND	       0x3F

static int fw_info_operation(struct hdl *hdl, op_get_info_args_t *op_args)
{
	int status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_get_info(hdl->session, op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_get_info returned %d\n", err);

	status = ele_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int device_repro_prepare(struct subsystem_context *ele_ctx,
				struct smw_devmgr_args *args)
{
	int status = SMW_STATUS_OK;

	unsigned char *msg = NULL;
	unsigned int msg_block_length = 0;
	unsigned int msg_length = 0;
	struct payload_reprovision *payload = NULL;
	op_get_info_args_t fw_info = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	msg_block_length = ele_get_sign_msg_block_length();
	msg_length = msg_block_length + PAYLOAD_LENGTH;
	msg = smw_devmgr_get_reprovision_data(args);
	if (!msg) {
		smw_devmgr_set_reprovision_length(args, msg_length);
		goto end;
	}

	if (smw_devmgr_get_reprovision_length(args) < msg_length) {
		smw_devmgr_set_reprovision_length(args, msg_length);
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		goto end;
	}

	ele_fill_sign_msg_block(msg, COMMAND, PAYLOAD_LENGTH);

	status = fw_info_operation(&ele_ctx->hdl, &fw_info);
	if (status == SMW_STATUS_OK) {
		payload = (void *)msg + msg_block_length;

		SMW_UTILS_MEMSET(payload, 0, PAYLOAD_LENGTH);

		payload->monotonic_counter = fw_info.chip_monotonic_counter;
		payload->user_sab_id = fw_info.user_sab_id;

		smw_devmgr_set_reprovision_length(args, msg_length);

		SMW_DBG_HEX_DUMP(DEBUG, msg, msg_length, 4);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int device_repro_send(struct subsystem_context *ele_ctx,
			     struct smw_devmgr_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	hsm_err_t err = HSM_NO_ERROR;

	bool srkh_fused = false;
	op_key_store_reprov_en_args_t op_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.signed_message = smw_devmgr_get_reprovision_data(args);
	op_args.signed_msg_size = smw_devmgr_get_reprovision_length(args);

	if (!op_args.signed_message || !op_args.signed_msg_size)
		goto end;

	status = ele_is_oem_srkh_fused(ele_ctx, &srkh_fused);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!srkh_fused) {
		status = SMW_STATUS_OEM_SRKH_NOT_FUSED;
		goto end;
	}

	err = hsm_key_store_reprov_en(ele_ctx->hdl.session, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_key_store_reprov_en returned %d\n", err);

	status = ele_convert_err(err);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

bool ele_device_reprovisioning_handle(struct subsystem_context *ele_ctx,
				      enum operation_id operation_id,
				      void *args, int *status)
{
	struct smw_devmgr_args *dev_args = args;

	SMW_DBG_ASSERT(args);

	if (operation_id != OPERATION_ID_DEVICE_REPROVISION)
		return false;

	switch (dev_args->op) {
	case SMW_OP_DEVMGR_REPROVISION_PREP:
		*status = device_repro_prepare(ele_ctx, args);
		break;

	case SMW_OP_DEVMGR_REPROVISION:
		*status = device_repro_send(ele_ctx, args);
		break;

	default:
		return false;
	}

	return true;
}
