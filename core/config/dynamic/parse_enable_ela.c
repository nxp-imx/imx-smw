// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdbool.h>

#include "smw_status.h"
#include "debug.h"
#include "utils.h"
#include "common.h"
#include "tag.h"

bool check_ela_tag(char **start, char *end, const char *buffer, int *status)
{
	char *cur = *start;

	/* Check if buffer contains USE_ELA tag */
	if (SMW_UTILS_STRNCMP(buffer, use_ela_tag,
			      SMW_UTILS_STRLEN(use_ela_tag)))
		return false;

	/* USE_ELA tag found - validate it's format */
	if (*status == SMW_STATUS_OK) {
		/* read_params_string() found PARAM=VALUE */
		SMW_DBG_PRINTF(ERROR, "USE_ELA shouldn't have a value\n");
		*status = SMW_STATUS_SYNTAX_ERROR;
		return false;
	}

	if (*status != SMW_STATUS_SYNTAX_ERROR)
		return false;

	if (*cur != semicolon)
		return false;

	/* Valid USE_ELA tag found, skip the semicolon */
	cur++;
	skip_insignificant_chars(&cur, end);

	SMW_DBG_PRINTF(INFO, "ELA tag enabled\n");

	*start = cur;
	*status = SMW_STATUS_OK;

	return true;
}
