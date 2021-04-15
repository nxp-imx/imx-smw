// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <tee_internal_api.h>

#include "tee_subsystem.h"
#include "ta_keymgr.h"
#include "ta_hash.h"
#include "ta_sign_verify.h"
#include "ta_hmac.h"
#include "ta_rng.h"

/**
 * TA_CreateEntryPoint() - Create entry point.
 *
 * First call in the TA. Called when the instance of the TA is created.
 *
 * Return:
 * TEE_SUCCESS	- Success.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	FMSG("Executing %s", __func__);
	return TEE_SUCCESS;
}

/**
 * Ta_DestroyEntryPoint() - Destroy entry point.
 *
 * Last call in the TA. Called when the instance of the TA is destroyed.
 *
 * Return:
 * none.
 */
void TA_DestroyEntryPoint(void)
{
	FMSG("Executing %s", __func__);
}

/**
 * Ta_OpenSessionEntryPoint() - Open session entry point.
 * @param_types: TEE parameters.
 * @params: Buffer parameters.
 * @sess_ctx: Session identifier.
 *
 * Called when a new session is opened to the TA. If return value != TEE_SUCCESS
 * the session will not be created.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- Bad parameters.
 */
TEE_Result
TA_OpenSessionEntryPoint(uint32_t param_types,
			 TEE_Param params[TEE_NUM_PARAMS] __maybe_unused,
			 void **sess_ctx __maybe_unused)
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	FMSG("Executing %s", __func__);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

/**
 * TA_CloseSessionEntryPoint() - Close session entry point.
 * @sess_ctx: Session Identifier.
 *
 * Called when a session is closed.
 *
 * Return:
 * none.
 */
void TA_CloseSessionEntryPoint(void *sess_ctx __maybe_unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	FMSG("Executing %s", __func__);

	/* Make sure to free transient resources */
	res = clear_key_linked_list();
	if (res)
		EMSG("Error while cleaning key linked list");
}

/**
 * TA_InvokeCommandEntryPoint() - Invoke command entry point.
 * @sess_ctx: Session Identifier.
 * @cmd_id: Command ID.
 * @param_types: TEE parameters.
 * @params: Buffer parameters.
 *
 * Called when a TA is invoked.
 *
 * Return:
 * TEE_SUCCESS			- Operation succeed.
 * TEE_ERROR_BAD_PARAMETERS	- Command ID is not implemented or parameters
 *                                are bad in specific command.
 * Other error code from specific command.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx __maybe_unused,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[TEE_NUM_PARAMS])
{
	FMSG("Executing %s", __func__);

	switch (cmd_id) {
	case CMD_GENERATE_KEY:
		return generate_key(param_types, params);
	case CMD_DELETE_KEY:
		return delete_key(param_types, params);
	case CMD_IMPORT_KEY:
		return import_key(param_types, params);
	case CMD_EXPORT_KEY:
		return export_key(param_types, params);
	case CMD_HASH:
		return hash(param_types, params);
	case CMD_SIGN:
	case CMD_VERIFY:
		return sign_verify(param_types, params, cmd_id);
	case CMD_HMAC:
		return hmac(param_types, params);
	case CMD_RNG:
		return rng(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
