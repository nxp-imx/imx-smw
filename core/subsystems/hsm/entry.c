// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <seco_nvm.h>
#include <hsm_api.h>

#include "smw_status.h"

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

#define STORAGE_MANAGER_TIMEOUT 1 /* s */

static struct {
	struct hdl hdl;
	uint32_t nvm_status;
	unsigned long tid;
	void *mutex;
} ctx = { .hdl = { .session = 0,
		   .key_store = 0,
		   .key_management = 0,
		   .signature_gen = 0,
		   .signature_ver = 0,
		   .hash = 0,
		   .rng = 0,
		   .cipher = 0 },
	  .nvm_status = NVM_STATUS_UNDEF,
	  .tid = 0,
	  .mutex = NULL };

static int open_session(hsm_hdl_t *session_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_session_args_t open_session_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_session(&open_session_args, session_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "session_hdl: %d\n", *session_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_session(hsm_hdl_t session_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "session_hdl: %d\n", session_hdl);
	err = hsm_close_session(session_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_key_store_service(hsm_hdl_t session_hdl,
				  hsm_hdl_t *key_store_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_key_store_args_t open_svc_key_store_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	open_svc_key_store_args.key_store_identifier = 0xDEADBEEF;
	open_svc_key_store_args.authentication_nonce = 0;
	open_svc_key_store_args.max_updates_number = 0;
	/* Key store may not exists. Try to create it */
	open_svc_key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	err = hsm_open_key_store_service(session_hdl, &open_svc_key_store_args,
					 key_store_hdl);
	if (err == HSM_ID_CONFLICT) {
		/* Key store already exists. Do not try to create it */
		open_svc_key_store_args.flags = 0;
		err = hsm_open_key_store_service(session_hdl,
						 &open_svc_key_store_args,
						 key_store_hdl);
	}
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %d\n", *key_store_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_key_store_service(hsm_hdl_t key_store_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %d\n", key_store_hdl);
	err = hsm_close_key_store_service(key_store_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_key_mgmt_service(hsm_hdl_t key_store_hdl,
				 hsm_hdl_t *key_management_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err;
	open_svc_key_management_args_t open_svc_key_management_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_key_management_service(key_store_hdl,
					      &open_svc_key_management_args,
					      key_management_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "key_management_hdl: %d\n", *key_management_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_key_management_service(hsm_hdl_t key_management_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "key_management_hdl: %d\n", key_management_hdl);
	err = hsm_close_key_management_service(key_management_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_signature_gen_service(hsm_hdl_t key_store_hdl,
				      hsm_hdl_t *signature_gen_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_sign_gen_args_t open_svc_sign_gen_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_signature_generation_service(key_store_hdl,
						    &open_svc_sign_gen_args,
						    signature_gen_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "signature_gen_hdl: %d\n", *signature_gen_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_signature_geneneration_service(hsm_hdl_t signature_gen_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "signature_gen_hdl: %d\n", signature_gen_hdl);
	err = hsm_close_signature_generation_service(signature_gen_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_signature_ver_service(hsm_hdl_t session_hdl,
				      hsm_hdl_t *signature_ver_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_sign_ver_args_t open_svc_sign_ver_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_signature_verification_service(session_hdl,
						      &open_svc_sign_ver_args,
						      signature_ver_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "signature_ver_hdl: %d\n", *signature_ver_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_signature_verification_service(hsm_hdl_t signature_ver_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "signature_ver_hdl: %d\n", signature_ver_hdl);
	err = hsm_close_signature_verification_service(signature_ver_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_hash_service(hsm_hdl_t session_hdl, hsm_hdl_t *hash_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_hash_args_t open_svc_hash_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_hash_service(session_hdl, &open_svc_hash_args, hash_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "hash_hdl: %d\n", *hash_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_hash_service(hsm_hdl_t hash_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "hash_hdl: %d\n", hash_hdl);
	err = hsm_close_hash_service(hash_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_rng_service(hsm_hdl_t session_hdl, hsm_hdl_t *rng_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_rng_args_t open_svc_rng_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_rng_service(session_hdl, &open_svc_rng_args, rng_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "rng_hdl: %d\n", *rng_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_rng_service(hsm_hdl_t rng_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "rng_hdl: %d\n", rng_hdl);
	err = hsm_close_rng_service(rng_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_cipher_service(hsm_hdl_t key_store_hdl, hsm_hdl_t *cipher_hdl)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;
	open_svc_cipher_args_t open_svc_cipher_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_cipher_service(key_store_hdl, &open_svc_cipher_args,
				      cipher_hdl);
	if (err != HSM_NO_ERROR) {
		SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
		goto end;
	}

	SMW_DBG_PRINTF(DEBUG, "cipher_hdl: %d\n", *cipher_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_cipher_service(hsm_hdl_t cipher_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "cipher_hdl: %d\n", cipher_hdl);
	err = hsm_close_cipher_service(cipher_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static void reset_handles(void)
{
	struct hdl *hdl = &ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (hdl->cipher)
		close_cipher_service(hdl->cipher);
	if (hdl->rng)
		close_rng_service(hdl->rng);
	if (hdl->hash)
		close_hash_service(hdl->hash);
	if (hdl->signature_ver)
		close_signature_verification_service(hdl->signature_ver);
	if (hdl->signature_gen)
		close_signature_geneneration_service(hdl->signature_gen);
	if (hdl->key_management)
		close_key_management_service(hdl->key_management);
	if (hdl->key_store)
		close_key_store_service(hdl->key_store);
	if (hdl->session)
		close_session(hdl->session);

	hdl->session = 0;
	hdl->key_store = 0;
	hdl->key_management = 0;
	hdl->signature_gen = 0;
	hdl->signature_ver = 0;
	hdl->hash = 0;
	hdl->rng = 0;
	hdl->cipher = 0;
}

static void *storage_thread(void *arg)
{
	(void)arg;

	SMW_DBG_TRACE_FUNCTION_CALL;

	seco_nvm_manager(NVM_FLAGS_HSM, &ctx.nvm_status);

	if (ctx.nvm_status >= NVM_STATUS_STOPPED)
		smw_config_notify_subsystem_failure(SUBSYSTEM_ID_HSM);

	smw_utils_mutex_lock(ctx.mutex);

	reset_handles();

	smw_utils_mutex_unlock(ctx.mutex);

	return NULL;
}

static int start_storage_manager(void)
{
	int status = SMW_STATUS_OK;

	unsigned long start_time = smw_utils_time(0);

	SMW_DBG_TRACE_FUNCTION_CALL;

	ctx.nvm_status = NVM_STATUS_UNDEF;

	if (smw_utils_thread_create(&ctx.tid, storage_thread, NULL)) {
		status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
		goto end;
	}

	SMW_DBG_PRINTF(DEBUG, "tid: %lx\n", ctx.tid);

	while (ctx.nvm_status <= NVM_STATUS_STARTING) {
		smw_utils_mutex_lock(ctx.mutex);
		SMW_DBG_PRINTF(DEBUG, "Storage manager status: %d\n",
			       ctx.nvm_status);
		smw_utils_mutex_unlock(ctx.mutex);
		if (smw_utils_time(start_time) >= STORAGE_MANAGER_TIMEOUT) {
			SMW_DBG_PRINTF(DEBUG,
				       "Storage manager failed to start (%d)\n",
				       ctx.nvm_status);
			(void)smw_utils_thread_cancel(ctx.tid);
			status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
			goto end;
		}
	}

	if (ctx.nvm_status >= NVM_STATUS_STOPPED) {
		SMW_DBG_PRINTF(DEBUG, "Storage manager stopped (%d)\n",
			       ctx.nvm_status);
		status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
		goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int stop_storage_manager(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "tid: %lx\n", ctx.tid);

	if (ctx.nvm_status != NVM_STATUS_STOPPED)
		if (smw_utils_thread_cancel(ctx.tid))
			status = SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int unload(void)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	reset_handles();

	status = stop_storage_manager();
	if (status != SMW_STATUS_OK)
		goto end;

	if (smw_utils_mutex_destroy(&ctx.mutex))
		status = SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE;

	/* Close Seco Session */
	seco_nvm_close_session();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int load(void)
{
	int status = SMW_STATUS_OK;

	struct hdl *hdl = &ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_init(&ctx.mutex)) {
		status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
		goto end;
	}

	status = start_storage_manager();
	if (status != SMW_STATUS_OK)
		goto end;

	smw_utils_mutex_lock(ctx.mutex);

	if (ctx.nvm_status >= NVM_STATUS_STOPPED)
		goto err;

	status = open_session(&hdl->session);
	if (status != SMW_STATUS_OK)
		goto err;

	status = open_key_store_service(hdl->session, &hdl->key_store);
	if (status != SMW_STATUS_OK)
		goto err;

	status = open_key_mgmt_service(hdl->key_store, &hdl->key_management);
	if (status != SMW_STATUS_OK)
		goto err;

	status =
		open_signature_gen_service(hdl->key_store, &hdl->signature_gen);
	if (status != SMW_STATUS_OK)
		goto err;

	status = open_signature_ver_service(hdl->session, &hdl->signature_ver);
	if (status != SMW_STATUS_OK)
		goto err;

	status = open_hash_service(hdl->session, &hdl->hash);

	if (status != SMW_STATUS_OK)
		goto err;

	status = open_rng_service(hdl->session, &hdl->rng);
	if (status != SMW_STATUS_OK)
		goto err;

	status = open_cipher_service(hdl->key_store, &hdl->cipher);

err:
	smw_utils_mutex_unlock(ctx.mutex);

	if (status != SMW_STATUS_OK)
		status = unload();

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak bool hsm_key_handle(struct hdl *hdl, enum operation_id operation_id,
			   void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool hsm_hash_handle(struct hdl *hdl, enum operation_id operation_id,
			    void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool hsm_sign_verify_handle(struct hdl *hdl,
				   enum operation_id operation_id, void *args,
				   int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool hsm_rng_handle(struct hdl *hdl, enum operation_id operation_id,
			   void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool hsm_cipher_handle(struct hdl *hdl, enum operation_id operation_id,
			      void *args, int *status)
{
	(void)hdl;
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

static int execute(enum operation_id operation_id, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct hdl *hdl = &ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (hsm_key_handle(hdl, operation_id, args, &status))
		goto end;
	else if (hsm_hash_handle(hdl, operation_id, args, &status))
		goto end;
	else if (hsm_sign_verify_handle(hdl, operation_id, args, &status))
		goto end;
	else if (hsm_rng_handle(hdl, operation_id, args, &status))
		goto end;

	hsm_cipher_handle(hdl, operation_id, args, &status);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static struct subsystem_func func = { .load = load,
				      .unload = unload,
				      .execute = execute };

struct subsystem_func *smw_hsm_get_func(void)
{
	return &func;
}

int convert_hsm_err(hsm_err_t err)
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
		status = SMW_STATUS_ALLOC_FAILURE;
		break;

	case HSM_UNKNOWN_ID:
		status = SMW_STATUS_UNKNOWN_ID;
		break;

	case HSM_FEATURE_NOT_SUPPORTED:
	case HSM_FEATURE_DISABLED:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;

	case HSM_KEY_STORE_CONFLICT:
	case HSM_KEY_STORE_AUTH:
	case HSM_NOT_READY_RATING:
		status = SMW_STATUS_OPERATION_FAILURE;
		break;

	default:
		break;
	}

	return status;
}
