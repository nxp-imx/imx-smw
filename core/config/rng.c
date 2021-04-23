// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "compiler.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "rng.h"

#include "common.h"

const char *rng_range = "RNG_RANGE";

static int rng_read_params(char **start, char *end, void **params)
{
	int status = SMW_STATUS_OK;
	char *cur = *start;

	char buffer[SMW_CONFIG_MAX_PARAMS_NAME_LENGTH + 1];
	int length;

	unsigned int length_min = 0;
	unsigned int length_max = UINT_MAX;

	struct rng_params *p;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (open_square_bracket != *cur)) {
		status = read_params_name(&cur, end, buffer);
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Parameter: %s\n", buffer);
		length = SMW_UTILS_STRLEN(buffer);

		skip_insignificant_chars(&cur, end);

		if (!SMW_UTILS_STRNCMP(buffer, rng_range, length)) {
			status =
				read_range(&cur, end, &length_min, &length_max);
			if (status != SMW_STATUS_OK)
				goto end;
		} else {
			status = skip_param(&cur, end);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		skip_insignificant_chars(&cur, end);
	}

	p = SMW_UTILS_MALLOC(sizeof(struct rng_params));
	if (!p) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p->operation_id = OPERATION_ID_RNG;
	p->length_min = length_min;
	p->length_max = length_max;

	*params = p;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__weak void rng_print_params(void *params)
{
	(void)params;
}

static bool check_random_number_length(unsigned int length,
				       unsigned int length_min,
				       unsigned int length_max)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return ((length >= length_min) && (length <= length_max)) ? true :
								    false;
}

static int rng_check_subsystem_caps(void *args, void *params)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_rng_args *rng_args = args;
	struct rng_params *rng_params = params;

	unsigned int length = smw_crypto_get_rng_output_length(rng_args);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_random_number_length(length, rng_params->length_min,
					rng_params->length_max))
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

DEFINE_CONFIG_OPERATION_FUNC(rng);
