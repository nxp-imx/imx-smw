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
#include "tee_subsystem.h"
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
	return false;
}

__weak bool tee_hash_handle(enum operation_id operation_id, void *args,
			    int *status)
{
	return false;
}

__weak bool tee_sign_verify_handle(enum operation_id operation_id, void *args,
				   int *status)
{
	return false;
}

__weak bool tee_hmac_handle(enum operation_id operation_id, void *args,
			    int *status)
{
	return false;
}

__weak bool tee_rng_handle(enum operation_id operation_id, void *args,
			   int *status)
{
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
		;
	else if (tee_hash_handle(op_id, args, &status))
		;
	else if (tee_sign_verify_handle(op_id, args, &status))
		;
	else if (tee_hmac_handle(op_id, args, &status))
		;
	else if (tee_rng_handle(op_id, args, &status))
		;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * convert_tee_result() - Convert TEE result into SMW status.
 * @result: TEE result.
 *
 * Return:
 * SMW status.
 */
static int convert_tee_result(TEEC_Result result)
{
	int status;

	switch (result) {
	case TEEC_SUCCESS:
		status = SMW_STATUS_OK;
		break;

	case TEEC_ERROR_SHORT_BUFFER:
		status = SMW_STATUS_OUTPUT_TOO_SHORT;
		break;

	case TEEC_ERROR_NOT_SUPPORTED:
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		break;

	case TEE_ERROR_SIGNATURE_INVALID:
		status = SMW_STATUS_SIGNATURE_INVALID;
		break;

	default:
		status = SMW_STATUS_SUBSYSTEM_FAILURE;
	}

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

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static struct subsystem_func func = { .load = load,
				      .unload = unload,
				      .execute = execute };

struct subsystem_func *smw_tee_get_func(void)
{
	return &func;
}
