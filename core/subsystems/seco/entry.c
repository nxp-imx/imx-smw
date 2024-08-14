// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2024 NXP
 */

#include <time.h>

#include "smw_osal.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

static struct subsystem_context seco_ctx = { 0 };

static int open_session(hsm_hdl_t *session_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_session_args_t open_session_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	open_session_args.mu_type = HSM1;

	err = hsm_open_session(&open_session_args, session_hdl);
	status = seco_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", *session_hdl);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_session(hsm_hdl_t session_hdl)
{
	hsm_err_t __maybe_unused err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", session_hdl);
	err = hsm_close_session(session_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_key_store_service(hsm_hdl_t session_hdl,
				  hsm_hdl_t *key_store_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_key_store_args_t open_svc_key_store_args = { 0 };
	struct se_info info = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_get_subsystem_info(SMW_SUBSYSTEM_NAME_SECO, &info)) {
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

	open_svc_key_store_args.key_store_identifier = info.storage_id;
	open_svc_key_store_args.authentication_nonce = info.storage_nonce;
	open_svc_key_store_args.max_updates_number = info.storage_replay;
	/* Key store may not exists. Try to create it */
	open_svc_key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	err = hsm_open_key_store_service(session_hdl, &open_svc_key_store_args,
					 key_store_hdl);
	if (err == HSM_ID_CONFLICT || err == HSM_KEY_STORE_CONFLICT) {
		/* Key store already exists. Do not try to create it */
		open_svc_key_store_args.flags = 0;
		err = hsm_open_key_store_service(session_hdl,
						 &open_svc_key_store_args,
						 key_store_hdl);
	}

	status = seco_convert_err(err);
	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", *key_store_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_key_store_service(hsm_hdl_t key_store_hdl)
{
	hsm_err_t __maybe_unused err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", key_store_hdl);
	err = hsm_close_key_store_service(key_store_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static void reset_handles(void)
{
	struct hdl *hdl = &seco_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (hdl->key_store)
		close_key_store_service(hdl->key_store);
	if (hdl->session)
		close_session(hdl->session);

	hdl->session = 0;
	hdl->key_store = 0;
}

static int unload(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	reset_handles();

	if (seco_ctx.key_grp_mutex) {
		if (smw_utils_mutex_lock(seco_ctx.key_grp_mutex))
			status = SMW_STATUS_MUTEX_LOCK_FAILURE;

		if (status == SMW_STATUS_OK) {
			smw_utils_list_destroy(&seco_ctx.key_grp_list);

			if (smw_utils_mutex_unlock(seco_ctx.key_grp_mutex))
				status = SMW_STATUS_MUTEX_UNLOCK_FAILURE;
		}

		if (status == SMW_STATUS_OK &&
		    smw_utils_mutex_destroy(&seco_ctx.key_grp_mutex))
			status = SMW_STATUS_MUTEX_DESTROY_FAILURE;
	}

	if (smw_utils_mutex_destroy(&seco_ctx.mutex) && status == SMW_STATUS_OK)
		status = SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int load(void)
{
	int status = SMW_STATUS_OK;

	struct hdl *hdl = &seco_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!seco_ctx.mutex && smw_utils_mutex_init(&seco_ctx.mutex)) {
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
		goto end;
	}

	status = open_session(&hdl->session);
	if (status != SMW_STATUS_OK)
		goto end;

	status = open_key_store_service(hdl->session, &hdl->key_store);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_utils_list_init(&seco_ctx.key_grp_list);

	if (smw_utils_mutex_init(&seco_ctx.key_grp_mutex)) {
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
		goto end;
	}

end:
	if (status != SMW_STATUS_OK)
		(void)unload();

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak bool seco_key_handle(struct subsystem_context *seco_ctx,
			    enum operation_id operation_id, void *args,
			    int *status)
{
	(void)seco_ctx;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_hash_handle(struct hdl *hdl, enum operation_id operation_id,
			     void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_sign_verify_handle(struct hdl *hdl,
				    enum operation_id operation_id, void *args,
				    int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_rng_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
			       void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_mac_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_storage_handle(struct hdl *hdl, enum operation_id operation_id,
				void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool seco_aead_handle(struct hdl *hdl, enum operation_id operation_id,
			     void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak void *seco_get_ctx_ops(void)
{
	return NULL;
}

static int execute(enum operation_id operation_id, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct hdl *hdl = &seco_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * To ensure that only one secure enclave service is called, lock
	 * a mutex.
	 */
	if (smw_utils_mutex_lock(seco_ctx.mutex)) {
		status = SMW_STATUS_MUTEX_LOCK_FAILURE;
		goto end;
	}

	if (seco_key_handle(&seco_ctx, operation_id, args, &status))
		goto end;
	else if (seco_hash_handle(hdl, operation_id, args, &status))
		goto end;
	else if (seco_sign_verify_handle(hdl, operation_id, args, &status))
		goto end;
	else if (seco_rng_handle(hdl, operation_id, args, &status))
		goto end;
	else if (seco_cipher_handle(hdl, operation_id, args, &status))
		goto end;
	else if (seco_mac_handle(hdl, operation_id, args, &status))
		goto end;
	else if (seco_storage_handle(hdl, operation_id, args, &status))
		goto end;

	seco_aead_handle(hdl, operation_id, args, &status);

end:
	if (smw_utils_mutex_unlock(seco_ctx.mutex) && status == SMW_STATUS_OK)
		status = SMW_STATUS_MUTEX_LOCK_FAILURE;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static const struct subsystem_func func = { .load = load,
					    .unload = unload,
					    .execute = execute,
					    .ctx_ops = seco_get_ctx_ops };

const struct subsystem_func *smw_seco_get_func(void)
{
	return &func;
}

int seco_convert_err(hsm_err_t err)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;

	switch (err) {
	case HSM_NO_ERROR:
		status = SMW_STATUS_OK;
		break;

	case HSM_INVALID_PARAM:
	case HSM_INVALID_MESSAGE:
	case HSM_INVALID_ADDRESS:
	case HSM_UNKNOWN_HANDLE:
	case HSM_UNKNOWN_KEY_STORE:
	case HSM_ID_CONFLICT:
		status = SMW_STATUS_INVALID_PARAM;
		break;

	case HSM_OUT_OF_MEMORY:
		status = SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
		break;

	case HSM_UNKNOWN_ID:
		status = SMW_STATUS_UNKNOWN_ID;
		break;

	case HSM_FEATURE_NOT_SUPPORTED:
	case HSM_FEATURE_DISABLED:
	case HSM_CMD_NOT_SUPPORTED:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;

	case HSM_KEY_STORE_CONFLICT:
	case HSM_KEY_STORE_AUTH:
	case HSM_NOT_READY_RATING:
	case HSM_RNG_NOT_STARTED:
	case HSM_KEY_STORE_COUNTER:
		status = SMW_STATUS_OPERATION_FAILURE;
		break;

	case HSM_NVM_ERROR:
	case HSM_KEY_STORE_ERROR:
		status = SMW_STATUS_SUBSYSTEM_STORAGE_ERROR;
		break;

	case HSM_SIGNATURE_INVALID:
		status = SMW_STATUS_SIGNATURE_INVALID;
		break;

	default:
		/*
		 * status = SMW_STATUS_SUBSYSTEM_FAILURE
		 * HSM_INVALID_LIFECYCLE
		 * HSM_SELF_TEST_FAILURE
		 * HSM_FATAL_FAILURE
		 * HSM_GENERAL_ERROR
		 */
		break;
	}

	return status;
}

int seco_open_key_mgmt_service(struct hdl *hdl, hsm_hdl_t *key_mgt_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;
	open_svc_key_management_args_t open_svc_key_management_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_key_management_service(hdl->key_store,
					      &open_svc_key_management_args,
					      key_mgt_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "Open key_mgt_hdl: %u\n", *key_mgt_hdl);

	return seco_convert_err(err);
}

int seco_close_key_mgt_service(hsm_hdl_t key_mgt_hdl)
{
	hsm_err_t err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Close key_mgt_hdl: %u\n", key_mgt_hdl);

	if (key_mgt_hdl) {
		err = hsm_close_key_management_service(key_mgt_hdl);
		SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
	}

	return seco_convert_err(err);
}
