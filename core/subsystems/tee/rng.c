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
#include "rng.h"
#include "tee.h"
#include "tee_subsystem.h"
#include "smw_status.h"

/**
 * hmac() - Call TA RNG operation.
 * @args: RNG arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int rng(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation operation = { 0 };

	struct smw_crypto_rng_args *rng_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!rng_args)
		goto exit;

	/*
	 * params[0] = Random number buffer
	 */
	operation.paramTypes =
		TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE,
				 TEEC_NONE);

	operation.params[0].tmpref.buffer =
		smw_crypto_get_rng_output_data(rng_args);
	operation.params[0].tmpref.size =
		smw_crypto_get_rng_output_length(rng_args);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_RNG, &operation);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_rng_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_RNG:
		*status = rng(args);
		break;
	default:
		return false;
	}

	return true;
}
