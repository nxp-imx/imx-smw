// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include "smw_osal.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

static struct subsystem_context ele_ctx = { 0 };

static int open_session(hsm_hdl_t *session_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_session_args_t open_session_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	open_session_args.mu_type = HSM1;

	err = hsm_open_session(&open_session_args, session_hdl);
	status = ele_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "hsm_open_session returned %d\n", err);
	SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", *session_hdl);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_session(struct hdl *hdl)
{
	hsm_err_t __maybe_unused err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (hdl->session) {
		SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", hdl->session);
		err = hsm_close_session(hdl->session);
		SMW_DBG_PRINTF(DEBUG, "hsm_close_session returned %d\n", err);

		hdl->session = HSM_HANDLE_NONE;
	}
}

int ele_open_key_store_service(struct hdl *hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_key_store_args_t open_svc_key_store_args = { 0 };
	struct se_info info = { 0 };
	uint8_t flags = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(hdl->key_store_mutex))
		return SMW_STATUS_MUTEX_LOCK_FAILURE;

	if (hdl->key_store) {
		if (!hdl->create_key_store)
			goto end;

		err = hsm_close_key_store_service(hdl->key_store);
		if (err != HSM_NO_ERROR)
			goto finish;

		hdl->key_store = HSM_HANDLE_NONE;
	}

	if (smw_utils_get_subsystem_info(SMW_SUBSYSTEM_NAME_ELE, &info)) {
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

	open_svc_key_store_args.key_store_identifier = info.storage_id;
	open_svc_key_store_args.authentication_nonce = info.storage_nonce;

	/* Key store may already exist */
	if (info.storage_shared)
		open_svc_key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_SHARED;

	if (!hdl->create_key_store) {
		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call hsm_open_key_store_service()\n"
			       "open_svc_key_store_args_t\n"
			       "    session_hdl: %x\n"
			       "    key_store_identifier: %x\n"
			       "    authentication_nonce: %x\n"
			       "    flags: %x\n",
			       __func__, __LINE__, hdl->session,
			       open_svc_key_store_args.key_store_identifier,
			       open_svc_key_store_args.authentication_nonce,
			       open_svc_key_store_args.flags);

		err = hsm_open_key_store_service(hdl->session,
						 &open_svc_key_store_args,
						 &hdl->key_store);

		SMW_DBG_PRINTF(DEBUG,
			       "hsm_open_key_store_service returned %d\n", err);

		if (err == HSM_NO_ERROR)
			goto finish;
	} else {
		/* Reset create key store flag */
		hdl->create_key_store = false;
	}

	/* Key store does not exist. Try to create it */
	flags = open_svc_key_store_args.flags;
	open_svc_key_store_args.flags |=
		HSM_SVC_KEY_STORE_FLAGS_CREATE |
		HSM_SVC_KEY_STORE_FLAGS_STRICT_OPERATION;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_open_key_store_service()\n"
		       "open_svc_key_store_args_t\n"
		       "    session_hdl: %x\n"
		       "    key_store_identifier: %x\n"
		       "    authentication_nonce: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, hdl->session,
		       open_svc_key_store_args.key_store_identifier,
		       open_svc_key_store_args.authentication_nonce,
		       open_svc_key_store_args.flags);

	err = hsm_open_key_store_service(hdl->session, &open_svc_key_store_args,
					 &hdl->key_store);

	SMW_DBG_PRINTF(DEBUG, "hsm_open_key_store_service returned %d\n", err);

	if (err == HSM_NO_ERROR)
		goto finish;

	/* Another application or thread may have created the key store in the meantime */
	open_svc_key_store_args.flags = flags;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_open_key_store_service()\n"
		       "open_svc_key_store_args_t\n"
		       "    session_hdl: %x\n"
		       "    key_store_identifier: %x\n"
		       "    authentication_nonce: %x\n"
		       "    flags: %x\n",
		       __func__, __LINE__, hdl->session,
		       open_svc_key_store_args.key_store_identifier,
		       open_svc_key_store_args.authentication_nonce,
		       open_svc_key_store_args.flags);

	err = hsm_open_key_store_service(hdl->session, &open_svc_key_store_args,
					 &hdl->key_store);

	SMW_DBG_PRINTF(DEBUG, "hsm_open_key_store_service returned %d\n", err);

finish:
	status = ele_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", *&hdl->key_store);

end:
	(void)smw_utils_mutex_unlock(hdl->key_store_mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_key_store_service(struct hdl *hdl)
{
	hsm_err_t __maybe_unused err = HSM_NO_ERROR;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(hdl->key_store_mutex))
		return;

	if (hdl->key_store) {
		SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", hdl->key_store);
		err = hsm_close_key_store_service(hdl->key_store);
		SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n",
			       "hsm_close_key_store_service", err);

		hdl->key_store = HSM_HANDLE_NONE;
	}

	(void)smw_utils_mutex_unlock(hdl->key_store_mutex);

	// coverity[locked_destroy]
	(void)smw_utils_mutex_destroy(&hdl->key_store_mutex);
}

static void reset_handles(void)
{
	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	close_key_store_service(hdl);
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

	if (status == SMW_STATUS_OK)
		status = tmp_status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int load(void)
{
	int status = SMW_STATUS_OK;

	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_init(&hdl->key_store_mutex)) {
		status = SMW_STATUS_MUTEX_INIT_FAILURE;
		goto end;
	}

	status = open_session(&hdl->session);
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

__weak bool ele_cipher_handle(struct subsystem_context *ele_ctx,
			      enum operation_id operation_id, void *args,
			      int *status)
{
	(void)ele_ctx;
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

__weak bool ele_aead_handle(struct subsystem_context *ele_ctx,
			    enum operation_id operation_id, void *args,
			    int *status)
{
	(void)ele_ctx;
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
	else if (ele_cipher_handle(&ele_ctx, operation_id, args, &status))
		goto end;
	else if (ele_mac_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_device_manager_handle(&ele_ctx, operation_id, args,
					   &status))
		goto end;
	else if (ele_storage_handle(&ele_ctx, operation_id, args, &status))
		goto end;
	else if (ele_aead_handle(&ele_ctx, operation_id, args, &status))
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

int ele_convert_err(hsm_err_t err)
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

	case HSM_NOT_READY_RATING:
	case HSM_RNG_NOT_STARTED:
	case HSM_KEY_STORE_COUNTER:
		status = SMW_STATUS_OPERATION_FAILURE;
		break;

	case HSM_NVM_ERROR:
	case HSM_KEY_STORE_ERROR:
	case HSM_KEY_STORE_CONFLICT:
	case HSM_KEY_STORE_AUTH:
		status = SMW_STATUS_SUBSYSTEM_STORAGE_ERROR;
		break;

	case HSM_OUT_TOO_SMALL:
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		break;

	case HSM_KEY_NOT_SUPPORTED:
		status = SMW_STATUS_KEY_INVALID;
		break;

	case HSM_SIGNATURE_INVALID:
		status = SMW_STATUS_SIGNATURE_INVALID;
		break;

	case HSM_INVALID_LIFECYCLE:
	case HSM_INVALID_LIFECYCLE_OP:
		status = SMW_STATUS_INVALID_LIFECYCLE;
		break;

	case HSM_LIB_ERR_IO_BUF_SETUP_OUT_OF_MEM:
		status = SMW_STATUS_INPUT_TOO_LARGE;
		break;

	default:
		/*
		 * status = SMW_STATUS_SUBSYSTEM_FAILURE
		 * HSM_SELF_TEST_FAILURE
		 * HSM_FATAL_FAILURE
		 * HSM_GENERAL_ERROR
		 */
		break;
	}

	return status;
}
