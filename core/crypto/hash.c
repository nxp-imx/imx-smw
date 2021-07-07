// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "hash.h"
#include "exec.h"

static int hash_convert_args(struct smw_hash_args *args,
			     struct smw_crypto_hash_args *converted_args,
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

	status = smw_config_get_hash_algo_id(args->algo_name,
					     &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_crypto_get_hash_input_data(struct smw_crypto_hash_args *args)
{
	unsigned char *input_data = NULL;

	if (args->pub)
		input_data = args->pub->input;

	return input_data;
}

unsigned int smw_crypto_get_hash_input_length(struct smw_crypto_hash_args *args)
{
	unsigned int input_length = 0;

	if (args->pub)
		input_length = args->pub->input_length;

	return input_length;
}

unsigned char *
smw_crypto_get_hash_output_data(struct smw_crypto_hash_args *args)
{
	unsigned char *output_data = NULL;

	if (args->pub)
		output_data = args->pub->output;

	return output_data;
}

unsigned int
smw_crypto_get_hash_output_length(struct smw_crypto_hash_args *args)
{
	unsigned int output_length = 0;

	if (args->pub)
		output_length = args->pub->output_length;

	return output_length;
}

void smw_crypto_set_hash_output_length(struct smw_crypto_hash_args *args,
				       unsigned int output_length)
{
	if (args->pub)
		args->pub->output_length = output_length;
}

enum smw_status_code smw_hash(struct smw_hash_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_hash_args hash_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || (args->output && (!args->input != !args->input_length ||
				       !args->output_length))) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = hash_convert_args(args, &hash_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_HASH, &hash_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
