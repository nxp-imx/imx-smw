// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "hmac.h"
#include "exec.h"

static int hmac_convert_args(struct smw_hmac_args *args,
			     struct smw_crypto_hmac_args *converted_args,
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

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
		goto end;

	status = smw_config_get_hmac_algo_id(args->algo_name,
					     &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_hmac_get_input_data(struct smw_crypto_hmac_args *args)
{
	unsigned char *input_data = NULL;

	if (args->pub)
		input_data = args->pub->input;

	return input_data;
}

unsigned int smw_hmac_get_input_length(struct smw_crypto_hmac_args *args)
{
	unsigned int input_length = 0;

	if (args->pub)
		input_length = args->pub->input_length;

	return input_length;
}

unsigned char *smw_hmac_get_output_data(struct smw_crypto_hmac_args *args)
{
	unsigned char *output_data = NULL;

	if (args->pub)
		output_data = args->pub->output;

	return output_data;
}

unsigned int smw_hmac_get_output_length(struct smw_crypto_hmac_args *args)
{
	unsigned int output_length = 0;

	if (args->pub)
		output_length = args->pub->output_length;

	return output_length;
}

void smw_hmac_set_output_length(struct smw_crypto_hmac_args *args,
				unsigned int output_length)
{
	if (args->pub)
		args->pub->output_length = output_length;
}

enum smw_status_code smw_hmac(struct smw_hmac_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_hmac_args hmac_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_descriptor;
	enum smw_keymgr_format_id format_id;
	unsigned char *private_data;
	unsigned int private_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->input || !args->input_length || !args->output ||
	    !args->output_length) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = hmac_convert_args(args, &hmac_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor = &hmac_args.key_descriptor;
	format_id = key_descriptor->format_id;
	private_data = smw_keymgr_get_private_data(key_descriptor);
	private_length = smw_keymgr_get_private_length(key_descriptor);
	if (format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		if (!private_data || !private_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	status = smw_utils_execute_operation(OPERATION_ID_HMAC, &hmac_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
