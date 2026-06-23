// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "config.h"
#include "keymgr.h"
#include "cipher.h"
#include "local.h"

/* ELA service context */
static struct ela_context ela_ctx = { 0 };

int convert_ela_err(prime_err_t err)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;

	switch (err) {
	case PRIME_ERR_NONE:
		status = SMW_STATUS_OK;
		break;

	case PRIME_ERR_INVALID_PARAM:
		status = SMW_STATUS_INVALID_PARAM;
		break;

	case PRIME_ERR_MEMORY_ALLOC:
		status = SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
		break;

	default:
		/*
		 * status = SMW_STATUS_SUBSYSTEM_FAILURE
		 * PRIME_ERR_SERVICE_OPEN
		 * PRIME_ERR_SERVICE_CLOSE
		 * PRIME_ERROR
		 */
		break;
	}

	return status;
}

int convert_fce_status(uint8_t status_code, uint8_t error_info)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* status_code FCE_STATUS_SUCCESS means success regardless of error_info */
	if (status_code == FCE_STATUS_SUCCESS) {
		/* error_info has informative value only, not an error */
		status = SMW_STATUS_OK;
	}
	/* For error status_code FCE_STATUS_ERROR, decode error_info */
	else if (status_code == FCE_STATUS_ERROR) {
		switch (error_info) {
		case FCE_ERR_INVALID_MESSAGE:
		case FCE_ERR_INVALID_REQ_ID:
		case FCE_ERR_PAYLOAD_SIZE:
		case FCE_ERR_TAG_SIZE:
			status = SMW_STATUS_INVALID_PARAM;
			break;

		case FCE_ERR_NOT_IMPLEMENTED:
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
			break;

		case FCE_ERR_FCE_REQ_ERROR:
		case FCE_ERR_PFWR_DIGEST:
		case FCE_ERR_FIFO_FULL:
			status = SMW_STATUS_OPERATION_FAILURE;
			break;

		case FCE_ERR_SERVICE_ALREADY_OPENED:
			status = SMW_STATUS_OPERATION_ALREADY_INIT;
			break;

		case FCE_ERR_NO_SLOTS:
			status = SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
			break;

		case FCE_ERR_KEY_SLOT_OUT_OF_RANGE:
			status = SMW_STATUS_SUBSYSTEM_STORAGE_NO_SPACE;
			break;

		case FCE_ERR_KEY_SIZE_INVALID:
			status = SMW_STATUS_KEY_INVALID;
			break;

		case FCE_ERR_INVALID_ALGO:
			status = SMW_STATUS_UNKNOWN_ALGO_NAME;
			break;

		case FCE_ERR_VERIFICATION_FAILED:
			status = SMW_STATUS_SIGNATURE_INVALID;
			break;

		default:
			status = SMW_STATUS_SUBSYSTEM_FAILURE;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s: FCE status=0x%02x info=0x%02x -> SMW=%d\n",
		       __func__, status_code, error_info, status);

	return status;
}

int ela_open_service(uint32_t size)
{
	int status = SMW_STATUS_OPERATION_FAILURE;

	prime_err_t err = PRIME_ERR_NONE;
	open_service_args_t op_serv_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (ela_ctx.service_hdl) {
		SMW_DBG_PRINTF(DEBUG, "ELA service already open\n");
		goto end;
	}

	op_serv_args.serv_type = SERVICE_TYPE_ALL;
	op_serv_args.size = size;
	err = prime_open_service(&op_serv_args, &ela_ctx.service_hdl);
	SMW_DBG_PRINTF(DEBUG, "prime_open_service returned %d\n", err);

	status = convert_ela_err(err);
	if (status != SMW_STATUS_OK)
		goto end;

	if (op_serv_args.size < size) {
		SMW_DBG_PRINTF(ERROR,
			       "Allocated size(%u) < requested size(%u)\n",
			       op_serv_args.size, size);
		status = SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
		goto end;
	}

	/* Store virtual and physical addresses for operations */
	ela_ctx.virtual_addr = (void *)op_serv_args.virtual_addr;
	ela_ctx.physical_addr = op_serv_args.physical_addr;
	ela_ctx.memory_size = op_serv_args.size;

	SMW_DBG_PRINTF(DEBUG,
		       "ELA service opened:\n"
		       "  service_hdl: %u\n"
		       "  virtual_addr: %p\n"
		       "  physical_addr: 0x%lx\n"
		       "  memory_size: %u\n",
		       ela_ctx.service_hdl, ela_ctx.virtual_addr,
		       ela_ctx.physical_addr, ela_ctx.memory_size);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void ela_close_service(void)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Close service if open */
	if (ela_ctx.service_hdl) {
		SMW_DBG_PRINTF(DEBUG, "Closing ELA service, service_hdl: %u\n",
			       ela_ctx.service_hdl);
		prime_close_service(ela_ctx.service_hdl);

		/* Clear context */
		ela_ctx.service_hdl = 0;
		ela_ctx.virtual_addr = NULL;
		ela_ctx.physical_addr = 0;
		ela_ctx.memory_size = 0;
	}
}

int ela_cleanup(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* ELA mutex not initialized, nothing to cleanup */
	if (!ela_ctx.mutex)
		goto end;

	/* Lock mutex before cleanup */
	if (smw_utils_mutex_lock(ela_ctx.mutex)) {
		status = SMW_STATUS_MUTEX_LOCK_FAILURE;
		SMW_DBG_PRINTF(ERROR, "Failed to lock mutex during cleanup\n");
		goto end;
	}

	ela_close_service();

	/* Unlock before destroying */
	if (smw_utils_mutex_unlock(ela_ctx.mutex)) {
		status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
		goto end;
	}

	/* Always destroy mutex during cleanup to prevent resource leak */
	if (smw_utils_mutex_destroy(&ela_ctx.mutex))
		status = SMW_STATUS_MUTEX_DESTROY_FAILURE;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int ela_init_mutex(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ela_ctx.mutex) {
		if (smw_utils_mutex_init(&ela_ctx.mutex)) {
			status = SMW_STATUS_MUTEX_INIT_FAILURE;
			SMW_DBG_PRINTF(ERROR,
				       "Failed to initialize ELA mutex\n");
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak bool ela_cipher_handle(enum operation_id operation_id, void *args,
			      int *status)
{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

bool ela_execute(struct subsystem_context *ele_ctx,
		 enum operation_id operation_id, void *args, int *status)
{
	int tmp_status = SMW_STATUS_OK;
	bool return_status = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!ele_ctx || !args || !status) {
		SMW_DBG_PRINTF(ERROR, "Invalid parameters\n");
		return return_status;
	}

	/* Get device information to check for ELA support */
	tmp_status = ele_get_device_info(ele_ctx);
	if (tmp_status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(DEBUG, "Failed to get device info\n");
		goto end;
	}

	if (!ele_ctx->info.ela) {
		SMW_DBG_PRINTF(DEBUG,
			       "Device does not support ELA (SoC ID: 0x%x)\n",
			       ele_ctx->info.soc_id);
		goto end;
	}

	SMW_DBG_PRINTF(DEBUG, "Device supports ELA (SoC ID: 0x%x)\n",
		       ele_ctx->info.soc_id);

	/* Mutex should already be initialized during subsystem load */
	if (!ela_ctx.mutex) {
		SMW_DBG_PRINTF(ERROR, "ELA mutex not initialized\n");
		goto end;
	}

	/*
	 * Acquire mutex for ELA operation serialization.
	 * ELA library lacks thread-safety, requiring exclusive access.
	 */
	if (smw_utils_mutex_lock(ela_ctx.mutex)) {
		SMW_DBG_PRINTF(ERROR, "Failed to lock ELA mutex\n");
		goto end;
	}

	return_status = ela_cipher_handle(operation_id, args, status);

	if (smw_utils_mutex_unlock(ela_ctx.mutex)) {
		SMW_DBG_PRINTF(ERROR, "Failed to unlock ELA mutex\n");
		return_status = false;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, *status);
	return return_status;
}

struct ela_context *ela_get_context(void)
{
	return &ela_ctx;
}
