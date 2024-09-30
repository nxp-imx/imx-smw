// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include "smw_status.h"

#include "operation_context.h"
#include "utils.h"
#include "subsystems.h"
#include "config.h"

/**
 * cancel_and_free_context() - Cancel and release the memory allocated to op ctx
 * @args: Pointer to SMW operation context arguments structure
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
static int cancel_and_free_context(struct smw_op_context **args, bool cancel_op)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	struct subsystem_func *subsystem_func = NULL;
	struct smw_crypto_context_ops *ops = NULL;

	enum subsystem_id subsystem_id = (*args)->subsystem_id;

	if (subsystem_id >= SUBSYSTEM_ID_NB ||
	    subsystem_id == SUBSYSTEM_ID_INVALID)
		goto end;

	subsystem_func = smw_config_get_subsystem_func(subsystem_id);
	if (!subsystem_func || !subsystem_func->ctx_ops) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	ops = subsystem_func->ctx_ops();
	if (!ops) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto end;
	}

	if ((*args)->op_state == CTX_OP_STATE_INIT) {
		if (cancel_op) {
			status = ops->cancel(*args);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		ops->free(args);
	}

	SMW_UTILS_FREE(*args);
	*args = NULL;

	status = smw_config_unload_subsystem(subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_free_context(struct smw_op_context **args)
{
	return cancel_and_free_context(args, false);
}

int smw_utils_cancel_operation(struct smw_op_context **args)
{
	return cancel_and_free_context(args, true);
}
