// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "tag.h"

#include "common.h"

static int device_attestation_read_params(char **start, char *end,
					  void **params)
{
	(void)params;

	int status = SMW_STATUS_OK;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = skip_param(&cur, end);
		if (status != SMW_STATUS_OK)
			goto end;

		skip_insignificant_chars(&cur, end);
	}

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void device_attestation_merge_params(void *caps, void *params)
{
	(void)caps;
	(void)params;

	SMW_DBG_TRACE_FUNCTION_CALL;
}

static void device_attestation_print_params(void *params)
{
	(void)params;
}

static int device_attestation_check_subsystem_caps(void *args, void *params)
{
	(void)args;
	(void)params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, SMW_STATUS_OK);
	return SMW_STATUS_OK;
}

DEFINE_CONFIG_OPERATION_FUNC(device_attestation);
