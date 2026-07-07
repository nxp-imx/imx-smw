// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "subsystems.h"
#include "rng.h"

#include "common.h"

#include "ele_rng.h"

int ele_rng_init(struct hdl *hdl)
{
	status_t err = STATUS_SUCCESS;
	uint32_t trng_state = 0u;

	err = ele_get_trng_state(hdl->mu_base, &trng_state);
	if (err != STATUS_SUCCESS)
		goto end;

	if (((trng_state & 0xFFu) == ELE_TRNG_READY) &&
	    ((trng_state & 0xFF00u) == ELE_TRNG_CSAL_SUCCESS << 8u))
		goto end;

	err = ele_start_rng(hdl->mu_base);
	if (err != STATUS_SUCCESS)
		goto end;

	do {
		err = ele_get_trng_state(hdl->mu_base, &trng_state);
	} while (((trng_state & 0xFFu) != ELE_TRNG_READY) &&
		 ((trng_state & 0xFF00u) != ELE_TRNG_CSAL_SUCCESS << 8u) &&
		 err == STATUS_SUCCESS);

end:
	return err;
}

static int rng(struct hdl *hdl, void *args)
{
	int status = SMW_STATUS_OK;

	status_t err = STATUS_SUCCESS;
	uint32_t *output = NULL;
	size_t size = 0;

	struct smw_crypto_rng_args *rng_args = args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	output = smw_crypto_get_rng_output_data(rng_args);
	size = smw_crypto_get_rng_output_length(rng_args);

	if (!output || !size)
		return SMW_STATUS_INVALID_PARAM;

	SMW_DBG_PRINTF(VERBOSE,
		       "[%s (%d)] Call ELE_RngGetRandom()\n"
		       "    Output\n"
		       "      - buffer: %p\n"
		       "      - size: %d\n",
		       __func__, __LINE__, output, size);

	err = ele_rng_get_random(hdl->mu_base, output, size, NORESEED);
	SMW_DBG_PRINTF(DEBUG, "ELE_RngGetRandom returned %d\n", err);

	status = ele_convert_err(err);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool ele_rng_handle(struct hdl *hdl, enum operation_id operation_id, void *args,
		    int *status)
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
