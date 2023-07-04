// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"

#include "debug.h"
#include "mac.h"
#include "utils.h"
#include "tee.h"

static int get_mac_algo(enum tee_algorithm_id *alg,
			struct smw_crypto_mac_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (args->algo_id) {
	case SMW_CONFIG_MAC_ALGO_ID_CMAC:
		*alg = TEE_ALGORITHM_ID_CMAC;
		status = SMW_STATUS_OK;
		break;

	case SMW_CONFIG_MAC_ALGO_ID_HMAC:
		status = tee_convert_hash_algorithm_id(args->hash_id, alg);
		break;

	default:
		*alg = TEE_ALGORITHM_ID_INVALID;
		break;
	}

	return status;
}

/**
 * mac() - Call TA mac operation.
 * @args: MAC arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int mac(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation op = { 0 };

	struct smw_crypto_mac_args *mac_args = args;
	struct smw_keymgr_descriptor *key_descriptor = NULL;
	struct smw_keymgr_identifier *key_identifier = NULL;
	unsigned int output_length = 0;

	uint32_t key_param_type = TEEC_VALUE_INPUT;
	uint32_t mac_param_type = TEEC_MEMREF_TEMP_INPUT;
	struct mac_shared_params shared_params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!mac_args)
		goto exit;

	key_descriptor = &mac_args->key_descriptor;
	key_identifier = &key_descriptor->identifier;

	status = tee_convert_key_type(key_identifier->type_id,
				      &shared_params.tee_key_type);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = get_mac_algo(&shared_params.tee_algorithm_id, mac_args);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * params[0] = Key ID or Key buffer
	 * params[1] = Key type ID / MAC algorithm ID and Security size
	 * params[2] = Message buffer and message length
	 * params[3] = MAC buffer and MAC length
	 */
	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		key_param_type = TEEC_MEMREF_TEMP_INPUT;
		op.params[0].tmpref.buffer =
			smw_keymgr_get_private_data(key_descriptor);
		op.params[0].tmpref.size =
			smw_keymgr_get_private_length(key_descriptor);
	} else {
		op.params[0].value.a = key_identifier->id;
	}

	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE)
		mac_param_type = TEEC_MEMREF_TEMP_OUTPUT;

	op.paramTypes =
		TEEC_PARAM_TYPES(key_param_type, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INPUT, mac_param_type);

	shared_params.security_size = key_identifier->security_size;

	op.params[1].tmpref.buffer = &shared_params;
	op.params[1].tmpref.size = sizeof(shared_params);
	op.params[2].tmpref.buffer = smw_mac_get_input_data(mac_args);
	op.params[2].tmpref.size = smw_mac_get_input_length(mac_args);
	op.params[3].tmpref.buffer = smw_mac_get_mac_data(mac_args);
	op.params[3].tmpref.size = smw_mac_get_mac_length(mac_args);

	/* Invoke TA */
	if (mac_args->op_id == SMW_CONFIG_MAC_OP_ID_COMPUTE) {
		status = execute_tee_cmd(CMD_MAC_COMPUTE, &op);
		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT) {
			if (!SET_OVERFLOW(op.params[3].tmpref.size,
					  output_length))
				smw_mac_set_mac_length(mac_args, output_length);
			else
				status = SMW_STATUS_OPERATION_FAILURE;
		}
	} else {
		status = execute_tee_cmd(CMD_MAC_VERIFY, &op);
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_mac_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_MAC:
		*status = mac(args);
		break;
	default:
		return false;
	}

	return true;
}
