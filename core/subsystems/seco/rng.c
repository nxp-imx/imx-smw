// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022, 2024 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "rng.h"

#include "common.h"

static int rng(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	hsm_err_t err = HSM_NO_ERROR;

	op_get_random_args_t op_args = { 0 };

	struct smw_crypto_rng_args *rng_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	op_args.output = smw_crypto_get_rng_output_data(rng_args);
	op_args.random_size = smw_crypto_get_rng_output_length(rng_args);

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call hsm_do_rng()\n"
		       "op_get_random_args_t\n"
		       "    Output\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, op_args.output, op_args.random_size);

	err = hsm_do_rng(hdl->session, &op_args);
	SMW_DBG_PRINTF(DEBUG, "hsm_do_rng returned %d\n", err);

	status = seco_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool seco_rng_handle(struct hdl *hdl, enum operation_id operation_id,
		     void *args, int *status)
{
	switch (operation_id) {
	case OPERATION_ID_RNG:
		*status = rng(hdl, args);
		break;
	default:
		return false;
	}

	return true;
}
