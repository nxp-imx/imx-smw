// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_osal.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

static struct {
	struct hdl hdl;
	unsigned long tid;
} ele_ctx = {
	.hdl = { .session = 0, .key_store = 0 },
	.tid = 0,
};

static int open_session(hsm_hdl_t *session_hdl)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;

	hsm_err_t err;
	open_session_args_t open_session_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	err = hsm_open_session(&open_session_args, session_hdl);
	status = ele_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);
	SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", *session_hdl);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_session(hsm_hdl_t session_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "session_hdl: %u\n", session_hdl);
	err = hsm_close_session(session_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static int open_key_store_service(hsm_hdl_t session_hdl,
				  hsm_hdl_t *key_store_hdl)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;

	hsm_err_t err;
	open_svc_key_store_args_t open_svc_key_store_args = { 0 };
	const char *subsystem_name;
	struct se_info info;

	SMW_DBG_TRACE_FUNCTION_CALL;
	subsystem_name = smw_config_get_subsystem_name(SUBSYSTEM_ID_ELE);

	if (smw_utils_get_subsystem_info(subsystem_name, &info)) {
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

	status = ele_convert_err(err);
	SMW_DBG_PRINTF(DEBUG, "%s - err: %d\n", __func__, err);

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", *key_store_hdl);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void close_key_store_service(hsm_hdl_t key_store_hdl)
{
	hsm_err_t __maybe_unused err;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", key_store_hdl);
	err = hsm_close_key_store_service(key_store_hdl);
	SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n", __func__, err);
}

static void reset_handles(void)
{
	struct hdl *hdl = &ele_ctx.hdl;

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

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int load(void)
{
	int status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;

	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = open_session(&hdl->session);
	if (status != SMW_STATUS_OK)
		goto end;

	status = open_key_store_service(hdl->session, &hdl->key_store);

end:
	if (status != SMW_STATUS_OK)
		(void)unload();

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak bool ele_key_handle(struct hdl *hdl, enum operation_id operation_id,
			   void *args, int *status)
{
	(void)hdl;
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

__weak bool ele_sign_verify_handle(struct hdl *hdl,
				   enum operation_id operation_id, void *args,
				   int *status)
{
	(void)hdl;
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

__weak bool ele_hmac_handle(struct hdl *hdl, enum operation_id operation_id,
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

	struct hdl *hdl = &ele_ctx.hdl;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (ele_key_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_hash_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_sign_verify_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_rng_handle(hdl, operation_id, args, &status))
		goto end;
	else if (ele_cipher_handle(hdl, operation_id, args, &status))
		goto end;

	ele_hmac_handle(hdl, operation_id, args, &status);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static const struct subsystem_func func = { .load = load,
					    .unload = unload,
					    .execute = execute };

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
