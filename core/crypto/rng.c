// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "rng.h"
#include "exec.h"

static int rng_convert_args(struct smw_rng_args *args,
			    struct smw_crypto_rng_args *converted_args,
			    enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_crypto_get_rng_output_data(struct smw_crypto_rng_args *args)
{
	unsigned char *output_data = NULL;

	if (args->pub)
		output_data = args->pub->output;

	return output_data;
}

unsigned int smw_crypto_get_rng_output_length(struct smw_crypto_rng_args *args)
{
	unsigned int output_length = 0;

	if (args->pub)
		output_length = args->pub->output_length;

	return output_length;
}

int smw_rng(struct smw_rng_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_rng_args rng_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->output || !args->output_length) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = rng_convert_args(args, &rng_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_RNG, &rng_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
