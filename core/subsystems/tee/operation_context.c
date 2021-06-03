// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "smw_osal.h"
#include "utils.h"
#include "config.h"
#include "tee.h"
#include "operation_context.h"

#include "smw_status.h"

/**
 * cancel_operation() - Call TA cancel operation
 * @args: Pointer to cancel operation arguments
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid
 */
static int cancel_operation(struct smw_crypto_cancel_op_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct shared_context shared_ctx;
	TEEC_Operation op = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	shared_ctx.handle = smw_crypto_get_cancel_handle(args);

	/*
	 * params[0] = Operation handle
	 * params[1] = None
	 * params[2] = None
	 * params[3] = None
	 */

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = &shared_ctx;
	op.params[0].tmpref.size = sizeof(shared_ctx);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_CANCEL_OP, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * copy_context() - Call TA copy context operation
 * @args: Pointer to copy context arguments
 *
 * Return:
 * SMW_STATUS_OK			- Success
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Subsystem failure
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation not supported by subsystem
 */
static int copy_context(struct smw_crypto_copy_ctx_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct shared_context src_ctx;
	struct shared_context dst_ctx = { 0 };
	TEEC_Operation op = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	src_ctx.handle = smw_crypto_get_copy_src_handle(args);

	/*
	 * params[0] = Source operation handle
	 * params[1] = Destination operation handle
	 * params[2] = None
	 * params[3] = None
	 */

	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INOUT,
				 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = &src_ctx;
	op.params[0].tmpref.size = sizeof(src_ctx);
	op.params[1].tmpref.buffer = &dst_ctx;
	op.params[1].tmpref.size = sizeof(dst_ctx);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_COPY_CTX, &op);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	smw_crypto_set_copy_dst_handle(args, dst_ctx.handle);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/* TEE context operations structure */
static struct smw_crypto_context_ops tee_ctx_ops = { .subsystem =
							     SUBSYSTEM_ID_TEE,
						     .cancel = cancel_operation,
						     .copy = copy_context };

struct smw_crypto_context_ops *tee_get_ctx_ops(void)
{
	return &tee_ctx_ops;
}
