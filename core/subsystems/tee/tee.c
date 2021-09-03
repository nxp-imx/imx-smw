// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <tee_client_api.h>

#include "compiler.h"
#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "smw_osal.h"
#include "utils.h"
#include "config.h"
#include "tee.h"
#include "smw_status.h"

/**
 * struct tee_subsystem - Context between Normal World and Secure World.
 * @context: Optee OS TA context.
 * @session: Optee OS TA session.
 */
struct tee_subsystem {
	TEEC_Context context;
	TEEC_Session session;
};

/* SMW-OPTEE OS global context */
static struct tee_subsystem tee_ctx;

__weak bool tee_key_handle(enum operation_id operation_id, void *args,
			   int *status)
{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool tee_hash_handle(enum operation_id operation_id, void *args,
			    int *status)
{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool tee_sign_verify_handle(enum operation_id operation_id, void *args,
				   int *status)
{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool tee_hmac_handle(enum operation_id operation_id, void *args,
			    int *status)
{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool tee_rng_handle(enum operation_id operation_id, void *args,
			   int *status)
{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

__weak bool tee_cipher_handle(enum operation_id operation_id, void *args,
			      int *status)

{
	(void)operation_id;
	(void)args;
	(void)status;

	return false;
}

/**
 * load() - Load optee os subsystem.
 *
 * Return:
 * SMW_STATUS_SUBSYSTEM_LOAD_FAILURE	- Failure.
 * SMW_STATUS_OK			- Success.
 */
static int load(void)
{
	TEEC_Result tee_res = TEEC_ERROR_GENERIC;
	TEEC_UUID ta_uuid = SMW_TA_UUID;
	int status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
	uint32_t err_origin = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	tee_res = TEEC_InitializeContext(NULL, &tee_ctx.context);
	if (tee_res != TEEC_SUCCESS) {
		SMW_DBG_PRINTF(ERROR, "Can't init TEE context: 0x%x\n",
			       tee_res);
		goto exit;
	}

	tee_res = TEEC_OpenSession(&tee_ctx.context, &tee_ctx.session, &ta_uuid,
				   TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (tee_res != TEEC_SUCCESS)
		SMW_DBG_PRINTF(ERROR, "Can't open TEE Session: 0x%x\n",
			       tee_res);
	else
		status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * unload() - Unload optee os subsystem.
 *
 * Return:
 * SMW_STATUS_OK	- Success.
 */
static int unload(void)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	TEEC_CloseSession(&tee_ctx.session);
	TEEC_FinalizeContext(&tee_ctx.context);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, SMW_STATUS_OK);
	return SMW_STATUS_OK;
}

/**
 * execute() - Execute operation.
 * @op_id: Operation ID.
 * @args: Operation arguments.
 *
 * Return:
 * SMW_STATUS_OK			- Operation succeeded.
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation not supported.
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Operation failed.
 */
static int execute(enum operation_id op_id, void *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (tee_key_handle(op_id, args, &status))
		goto end;
	else if (tee_hash_handle(op_id, args, &status))
		goto end;
	else if (tee_sign_verify_handle(op_id, args, &status))
		goto end;
	else if (tee_hmac_handle(op_id, args, &status))
		goto end;
	else if (tee_rng_handle(op_id, args, &status))
		goto end;

	tee_cipher_handle(op_id, args, &status);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int convert_tee_result(TEEC_Result result)
{
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;

	switch (result) {
	case TEEC_SUCCESS:
		status = SMW_STATUS_OK;
		break;

	case TEEC_ERROR_SHORT_BUFFER:
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		break;

	case TEEC_ERROR_NOT_SUPPORTED:
	case TEEC_ERROR_NOT_IMPLEMENTED:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;

	case TEE_ERROR_OVERFLOW:
	case TEE_ERROR_TIME_NOT_SET:
	case TEEC_ERROR_BAD_PARAMETERS:
	case TEEC_ERROR_SECURITY:
	case TEEC_ERROR_BAD_FORMAT:
	case TEEC_ERROR_BAD_STATE:
	case TEEC_ERROR_NO_DATA:
		status = SMW_STATUS_INVALID_PARAM;
		break;

	case TEEC_ERROR_ITEM_NOT_FOUND:
		status = SMW_STATUS_UNKNOWN_ID;
		break;

	case TEE_ERROR_SIGNATURE_INVALID:
		status = SMW_STATUS_SIGNATURE_INVALID;
		break;

	case TEE_ERROR_STORAGE_NO_SPACE:
		status = SMW_STATUS_SUBSYSTEM_STORAGE_NO_SPACE;
		break;

	case TEEC_ERROR_OUT_OF_MEMORY:
		status = SMW_STATUS_SUBSYSTEM_OUT_OF_MEMORY;
		break;

	case TEE_ERROR_STORAGE_NOT_AVAILABLE:
	case TEE_ERROR_STORAGE_NOT_AVAILABLE_2:
		status = SMW_STATUS_SUBSYSTEM_STORAGE_ERROR;
		break;

	case TEE_ERROR_CORRUPT_OBJECT:
	case TEE_ERROR_CORRUPT_OBJECT_2:
		status = SMW_STATUS_SUBSYSTEM_CORRUPT_OBJECT;
		break;

	case TEE_ERROR_TIME_NEEDS_RESET:
	case TEEC_ERROR_ACCESS_DENIED:
	case TEEC_ERROR_CANCEL:
	case TEEC_ERROR_BUSY:
	case TEEC_ERROR_EXTERNAL_CANCEL:
	case TEEC_ERROR_ACCESS_CONFLICT:
	case TEEC_ERROR_EXCESS_DATA:
		status = SMW_STATUS_OPERATION_FAILURE;
		break;

	default:
		/*
		 * status = SMW_STATUS_SUBSYSTEM_FAILURE
		 * TEEC_ERROR_GENERIC
		 * TEEC_ERROR_COMMUNICATION
		 * TEEC_ERROR_TARGET_DEAD
		 */
		break;
	}

	/*
	 * To handle when feature will be supported:
	 * - TEE_ERROR_CIPHERTEXT_INVALID (AsymmetricEncrypt, AsymmetricDecrypt)
	 * - TEE_ERROR_MAC_INVALID (MACCompareFinal, AEDecryptFinal)
	 */

	return status;
}

int execute_tee_cmd(uint32_t cmd_id, TEEC_Operation *op)
{
	TEEC_Result tee_res = TEEC_ERROR_GENERIC;
	int status = SMW_STATUS_SUBSYSTEM_FAILURE;
	uint32_t err_origin = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	tee_res = TEEC_InvokeCommand(&tee_ctx.session, cmd_id, op, &err_origin);

	status = convert_tee_result(tee_res);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d (%x)\n", __func__, status,
		       tee_res);
	return status;
}

TEEC_Context *get_tee_context_ptr(void)
{
	return &tee_ctx.context;
}

static struct subsystem_func func = { .load = load,
				      .unload = unload,
				      .execute = execute };

struct subsystem_func *smw_tee_get_func(void)
{
	return &func;
}
