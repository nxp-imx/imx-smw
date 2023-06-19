// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "rng.h"

#include "common.h"
#include "tag.h"

static int rng_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1] = { 0 };
	size_t length = 0;

	struct range range = { 0 };
	struct rng_params *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	range.min = 0;
	range.max = UINT_MAX;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, rng_range, length)) {
			status = read_range(&cur, end, &range);
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	p = SMW_UTILS_MALLOC(sizeof(*p));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->range = range;

	*params = p;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void rng_merge_params(void *caps, void *params)
{
	struct rng_params *rng_caps = caps;
	struct rng_params *rng_params = params;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (rng_caps->range.min > rng_params->range.min)
		rng_caps->range.min = rng_params->range.min;
	if (rng_caps->range.max < rng_params->range.max)
		rng_caps->range.max = rng_params->range.max;
}

__weak void rng_print_params(void *params)
{
	(void)params;
}

static int rng_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_rng_args *rng_args = args;
	struct rng_params *rng_params = params;

	unsigned int length = smw_crypto_get_rng_output_length(rng_args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_size(length, &rng_params->range))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(rng);
