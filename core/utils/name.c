// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"

int smw_utils_get_string_index(const char *name, const char *const array[],
			       unsigned int size, unsigned int *id)
{
	int status = SMW_STATUS_UNKNOWN_NAME;

	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(name);

	for (; i < size; i++) {
		if (array[i] && *array[i]) {
			if (!SMW_UTILS_STRCMP(array[i], name)) {
				status = SMW_STATUS_OK;
				*id = i;
				break;
			}
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
