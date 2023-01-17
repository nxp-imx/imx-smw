// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_crypto.h"

#include "debug.h"
#include "mac.h"
#include "exec.h"

static int mac_convert_args(struct smw_mac_args *args,
			    struct smw_crypto_mac_args *converted_args,
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

	status = smw_config_get_mac_algo_id(args->algo_name,
					    &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_get_hash_algo_id(args->hash_name,
					     &converted_args->hash_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static enum smw_status_code mac_operate(struct smw_mac_args *args,
					enum smw_config_mac_op_type_id op_id)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_mac_args mac_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_descriptor;
	enum smw_keymgr_format_id format_id;
	unsigned char *private_data;
	unsigned int private_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if ((!args->mac && args->mac_length) ||
	    (args->mac && !args->mac_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/* Cipher MAC of an empty message is valid */
	if ((!args->input && args->input_length) ||
	    (args->input && !args->input_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = mac_convert_args(args, &mac_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor = &mac_args.key_descriptor;
	format_id = key_descriptor->format_id;
	private_data = smw_keymgr_get_private_data(key_descriptor);
	private_length = smw_keymgr_get_private_length(key_descriptor);
	if (format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		if (!private_data || !private_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	mac_args.op_id = op_id;
	status = smw_utils_execute_operation(OPERATION_ID_MAC, &mac_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_mac_get_input_data(struct smw_crypto_mac_args *args)
{
	unsigned char *input_data = NULL;

	if (args->pub)
		input_data = args->pub->input;

	return input_data;
}

unsigned int smw_mac_get_input_length(struct smw_crypto_mac_args *args)
{
	unsigned int input_length = 0;

	if (args->pub)
		input_length = args->pub->input_length;

	return input_length;
}

unsigned char *smw_mac_get_mac_data(struct smw_crypto_mac_args *args)
{
	unsigned char *mac_data = NULL;

	if (args->pub)
		mac_data = args->pub->mac;

	return mac_data;
}

unsigned int smw_mac_get_mac_length(struct smw_crypto_mac_args *args)
{
	unsigned int mac_length = 0;

	if (args->pub)
		mac_length = args->pub->mac_length;

	return mac_length;
}

void smw_mac_set_mac_length(struct smw_crypto_mac_args *args,
			    unsigned int mac_length)
{
	if (args->pub)
		args->pub->mac_length = mac_length;
}

enum smw_status_code smw_mac(struct smw_mac_args *args)
{
	return mac_operate(args, SMW_CONFIG_MAC_OP_ID_COMPUTE);
}

enum smw_status_code smw_mac_verify(struct smw_mac_args *args)
{
	return mac_operate(args, SMW_CONFIG_MAC_OP_ID_VERIFY);
}
