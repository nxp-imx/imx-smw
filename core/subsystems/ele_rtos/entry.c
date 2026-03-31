// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_osal.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "utils_ex.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

#include "ele_crypto.h"

static struct subsystem_context ele_ctx = { 0 };

static int open_session(struct hdl *hdl)
{
	int status = SMW_STATUS_OK;
	status_t err = kStatus_Success;

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = ele_open_session(hdl->mu_base, &hdl->session);
	SMW_DBG_PRINTF(DEBUG, "ele_open_session returned %d\n", err);
	if (err != kStatus_Success)
		goto end;

	SMW_DBG_PRINTF(DEBUG, "session: %u\n", hdl->session);

end:
	status = ele_convert_err(err);
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_session(struct hdl *hdl)
{
	status_t err = kStatus_Success;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (hdl->session) {
		SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", hdl->session);
		err = ele_close_session(hdl->mu_base, hdl->session);
		SMW_DBG_PRINTF(DEBUG, "ele_close_session returned %d\n", err);

		hdl->session = 0;
	}
}

static void reset_handles(void)
{
	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	close_session(hdl);

	// coverity[missing_unlock]
}

static int unload(void)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	reset_handles();

	if (ele_ctx.key_grp_mutex) {
		if (smw_utils_mutex_lock(ele_ctx.key_grp_mutex))
			status = SMW_STATUS_MUTEX_LOCK_FAILURE;

		if (status == SMW_STATUS_OK) {
			smw_utils_list_destroy(&ele_ctx.key_grp_list);

			if (smw_utils_mutex_unlock(ele_ctx.key_grp_mutex))
				status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
		}

		if (status == SMW_STATUS_OK &&
		    smw_utils_mutex_destroy(&ele_ctx.key_grp_mutex))
			status = SMW_STATUS_MUTEX_DESTROY_FAILURE;
	}

	if (ele_ctx.info.mutex) {
		if (smw_utils_mutex_lock(ele_ctx.info.mutex))
			tmp_status = SMW_STATUS_MUTEX_LOCK_FAILURE;

		if (tmp_status == SMW_STATUS_OK) {
			if (ele_ctx.info.uid)
				SMW_UTILS_FREE(ele_ctx.info.uid);

			ele_ctx.info.valid = false;

			if (smw_utils_mutex_unlock(ele_ctx.info.mutex))
				tmp_status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
		}

		if (tmp_status == SMW_STATUS_OK &&
		    smw_utils_mutex_destroy(&ele_ctx.info.mutex))
			tmp_status = SMW_STATUS_MUTEX_DESTROY_FAILURE;
	}

	smw_utils_shared_memory_deinit();

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int load(void)
{
	status_t err = kStatus_Success;
	int status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
	uint32_t ele_version = 0;

	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_init(&hdl->key_store_mutex)) {
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
		goto end;
	}

	hdl->mu_base = smw_utils_get_mu_base();

	smw_utils_shared_memory_init();

	err = ele_ping(hdl->mu_base);
	if (err != kStatus_Success)
		goto end;

	err = ele_rng_init(hdl);
	if (err != kStatus_Success)
		goto end;

	err = ele_init_services(hdl->mu_base);
	if (err != kStatus_Success)
		goto end;

	err = ele_get_fw_version(hdl->mu_base, &ele_version);
	if (err != kStatus_Success)
		goto end;

	SMW_DBG_PRINTF(VERBOSE, "ELE version %d\n", ele_version);

	status = open_session(hdl);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_utils_list_init(&ele_ctx.key_grp_list);

	if (smw_utils_mutex_init(&ele_ctx.key_grp_mutex)) {
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
		goto end;
	}

	if (smw_utils_mutex_init(&ele_ctx.info.mutex))
		status = SMW_STATUS_MUTEX_INIT_FAILURE;

end:
	if (status != SMW_STATUS_OK)
		(void)unload();

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak bool ele_key_handle(struct subsystem_context *ele_ctx,
			   enum operation_id operation_id, void *args,
			   int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_hash_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_sign_verify_handle(struct subsystem_context *ele_ctx,
				   enum operation_id operation_id, void *args,
				   int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_rng_handle(struct hdl *hdl, enum operation_id operation_id,
			   void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
			      void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_mac_handle(struct hdl *hdl, enum operation_id operation_id,
			   void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_device_manager_handle(struct subsystem_context *ele_ctx,
				      enum operation_id operation_id,
				      void *args, int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_storage_handle(struct subsystem_context *ele_ctx,
			       enum operation_id operation_id, void *args,
			       int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_aead_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool ele_asymmetric_encryption_handle(struct subsystem_context *ele_ctx,
					     enum operation_id operation_id,
					     void *args, int *status)
{
	(void)ele_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak void *ele_get_ctx_ops(void)
{
	return NULL;
}

static int execute(enum operation_id operation_id, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (ele_key_handle(&ele_ctx, operation_id, args, &status))
		goto end;
	else if (ele_hash_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_sign_verify_handle(&ele_ctx, operation_id, args, &status))
		goto end;
	else if (ele_rng_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_cipher_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_mac_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_device_manager_handle(&ele_ctx, operation_id, args,
					   &status))
		goto end;
	else if (ele_storage_handle(&ele_ctx, operation_id, args, &status))
		goto end;
	else if (ele_aead_handle(hdl, operation_id, args, &status))
		goto end;

	ele_asymmetric_encryption_handle(&ele_ctx, operation_id, args, &status);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static const struct subsystem_func func = { .load = load,
					    .unload = unload,
					    .execute = execute,
					    .ctx_ops = ele_get_ctx_ops };

const struct subsystem_func *smw_ele_get_func(void)
{
	return &func;
}

int ele_convert_err(uint32_t err)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;

	switch (err) {
	case kStatus_Success:
		status = SMW_STATUS_OK;
		break;

	case kStatus_InvalidArgument:
		status = SMW_STATUS_INVALID_PARAM;
		break;

	case kStatus_ELE_BufferTooSmall:
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		break;

	default:
		/*
		 * status = SMW_STATUS_SUBSYSTEM_FAILURE
		 */
		break;
	}

	return status;
}
