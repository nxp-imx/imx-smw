// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "math.h"

int smw_utils_align_value(unsigned int value, unsigned int alignment,
			  unsigned int *result)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int mask = 0;
	unsigned int aligned = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!result)
		goto end;

	if (SUB_OVERFLOW(alignment, 1, &mask))
		goto end;

	if (ADD_OVERFLOW(value, mask, &aligned))
		goto end;

	*result = aligned & ~mask;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
