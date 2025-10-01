// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include "smw_status.h"

#include "operation_context.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"

/**
 * cancel_and_free_context() - Cancel and release the memory allocated to op ctx
 * @op_context: Pointer to SMW operation context arguments structure
 * @cancel_op: True, if operation must be cancelled prior to releasing the ctx
 *
 * If the context operation state is CTX_OP_STATE_INIT, this function calls the
 * subsystem wrapper to cancel the on-going multipart operation only if
 * @cancel_op is set. Then, subsystem wrapper releases the memory allocated to
 * subsystem specific context.
 * Finally, the memory allocated to the SMW operation context is released.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Operation not supported
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 */
static int cancel_and_free_context(struct smw_op_context **op_context,
				   bool cancel_op)
{
	int status = SMW_STATUS_OK;

	struct subsystem_func *subsystem_func = NULL;
	struct smw_crypto_context_ops *ops = NULL;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	if ((*op_context)->op_state == CTX_OP_STATE_ALLOC) {
		/* Nothing to cancel, just free the context */
		SMW_UTILS_FREE(*op_context);
		*op_context = NULL;
		goto end;
	}

	status = smw_crypto_get_ctx_subsystem_id(*op_context, &subsystem_id);
	if (status == SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME) {
		status = SMW_STATUS_OK;
		goto end;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	subsystem_func = smw_config_get_subsystem_func(subsystem_id);
	if (!subsystem_func || !subsystem_func->ctx_ops)
		goto end;

	ops = subsystem_func->ctx_ops();
	if (!ops)
		goto end;

	if ((*op_context)->op_state == CTX_OP_STATE_INIT) {
		if (cancel_op) {
			status = ops->cancel(*op_context);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		ops->free(*op_context);
	}

	SMW_UTILS_FREE(*op_context);
	*op_context = NULL;

	status = smw_config_unload_subsystem(subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_free_context(struct smw_op_context **op_context)
{
	return cancel_and_free_context(op_context, false);
}

int smw_utils_cancel_operation(struct smw_op_context **op_context)
{
	return cancel_and_free_context(op_context, true);
}
