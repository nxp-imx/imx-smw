// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "debug.h"
#include "lifecycle.h"
#include "devmgr.h"
#include "utils.h"

#include "local.h"

#define LIFECYCLE(_smw, _ele)                                                  \
	{                                                                      \
		.smw = SMW_LIFECYCLE_ID_##_smw, .ele = HSM_##_ele##_STATE      \
	}

static const struct lifecycle {
	enum smw_lifecycle_id smw;
	hsm_lc_new_state_t ele;
} lifecycles[] = { LIFECYCLE(OPEN, OEM_OPEN), LIFECYCLE(CLOSED, OEM_CLOSE),
		   LIFECYCLE(CLOSED_LOCKED, OEM_LOCKED),
		   LIFECYCLE(OEM_RETURN, OEM_FIELD_RET),
		   LIFECYCLE(NXP_RETURN, NXP_FIELD_RET) };

static int lifecycle_smw_to_ele(unsigned int smw_lc, hsm_lc_new_state_t *ele_lc)
{
	int status = SMW_STATUS_INVALID_LIFECYCLE;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(lifecycles); i++) {
		if (lifecycles[i].smw == smw_lc) {
			*ele_lc = lifecycles[i].ele;
			status = SMW_STATUS_OK;
			break;
		}
	}

	return status;
}

static int set_lifecycle_operation(struct hdl *hdl,
				   struct smw_devmgr_lifecycle_args *args)
{
	int status = SMW_STATUS_OK;
	hsm_err_t err = HSM_NO_ERROR;

	op_lc_update_msg_args_t op = { 0 };

	status = lifecycle_smw_to_ele(args->lifecycle_id, &op.new_lc_state);
	if (status == SMW_STATUS_OK) {
		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_lc_update()\n"
			       "    lifecycle: 0x%04X\n",
			       __func__, __LINE__, op.new_lc_state);

		err = hsm_lc_update(hdl->session, &op);
		SMW_DBG_PRINTF(DEBUG, "hsm_lc_update returned %d\n", err);

		status = ele_convert_err(err);
	}

	return status;
}

static int device_lifecycle(struct subsystem_context *ele_ctx, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_devmgr_lifecycle_args *op_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (op_args->op == SMW_OP_DEVMGR_SET_LIFECYCLE)
		status = set_lifecycle_operation(&ele_ctx->hdl, op_args);
	else if (op_args->op == SMW_OP_DEVMGR_GET_LIFECYCLE)
		status = ele_get_device_lifecycle_id(ele_ctx,
						     &op_args->lifecycle_id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	return status;
}

bool ele_device_lifecycle_handle(struct subsystem_context *ele_ctx,
				 enum operation_id operation_id, void *args,
				 int *status)
{
	SMW_DBG_ASSERT(args);

	switch (operation_id) {
	case OPERATION_ID_DEVICE_LIFECYCLE:
		*status = device_lifecycle(ele_ctx, args);
		break;

	default:
		return false;
	}

	return true;
}
