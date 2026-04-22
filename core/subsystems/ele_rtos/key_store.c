// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_osal.h"

#include "debug.h"
#include "utils.h"

#include "common.h"
#include "ele_crypto_keystore.h"

int ele_open_key_store_service(struct hdl *hdl)
{
	int status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;
	ele_keystore_t keystoreParam = { 0 };
	struct se_info info = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(hdl->key_store_mutex))
		return SMW_STATUS_MUTEX_LOCK_FAILURE;

	if (hdl->key_store) {
		if (!hdl->create_key_store)
			goto end;

		err = ele_close_keystore(hdl->mu_base, hdl->key_store);
		if (err != STATUS_SUCCESS)
			goto finish;

		hdl->key_store = 0;
	}

	if (smw_utils_get_subsystem_info(SMW_SUBSYSTEM_NAME_ELE, &info)) {
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

	keystoreParam.id = info.storage_id;
	keystoreParam.nonce = info.storage_nonce;

	/* Key store may already exist */
	keystoreParam.shared = info.storage_shared;

	if (!hdl->create_key_store) {
		SMW_DBG_PRINTF(VERBOSE,
			       "[%s (%d)] Call ele_open_keystore()\n"
			       "    session_hdl: %x\n"
			       "    key_store_identifier: %x\n"
			       "    authentication_nonce: %x\n"
			       "    shared: %x\n",
			       __func__, __LINE__, hdl->session,
			       keystoreParam.id, keystoreParam.nonce,
			       keystoreParam.shared);

		err = ele_open_keystore(hdl->mu_base, hdl->session,
					&keystoreParam, &hdl->key_store, NULL,
					0);

		SMW_DBG_PRINTF(DEBUG, "ele_open_keystore returned %d\n", err);

		if (err == STATUS_SUCCESS)
			goto finish;
	} else {
		/* Reset create key store flag */
		hdl->create_key_store = false;
	}

	/* Key store does not exist. Try to create it */
	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ele_create_keystore()\n"
		       "    session_hdl: %x\n"
		       "    key_store_identifier: %x\n"
		       "    authentication_nonce: %x\n"
		       "    shared: %x\n",
		       __func__, __LINE__, hdl->session, keystoreParam.id,
		       keystoreParam.nonce, keystoreParam.shared);

	err = ele_create_keystore(hdl->mu_base, hdl->session, &keystoreParam,
				  &hdl->key_store);

	SMW_DBG_PRINTF(DEBUG, "ele_create_keystore returned %d\n", err);

finish:
	status = ele_convert_err(err);

	SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", *&hdl->key_store);

end:
	(void)smw_utils_mutex_unlock(hdl->key_store_mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void ele_close_key_store_service(struct hdl *hdl)
{
	status_t status = STATUS_SUCCESS;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (smw_utils_mutex_lock(hdl->key_store_mutex))
		return;

	if (hdl->key_store) {
		SMW_DBG_PRINTF(DEBUG, "key_store_hdl: %u\n", hdl->key_store);
		status = ele_close_keystore(hdl->mu_base, hdl->key_store);
		SMW_DBG_PRINTF(DEBUG, "%s - returned: %d\n",
			       "hsm_close_key_store_service", status);

		hdl->key_store = 0;
	}

	(void)smw_utils_mutex_unlock(hdl->key_store_mutex);

	// coverity[locked_destroy]
	(void)smw_utils_mutex_destroy(&hdl->key_store_mutex);
}
