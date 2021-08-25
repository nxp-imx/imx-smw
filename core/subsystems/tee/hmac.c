// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "smw_osal.h"
#include "utils.h"
#include "config.h"
#include "keymgr.h"
#include "hmac.h"
#include "tee.h"
#include "smw_status.h"

#define ALGORITHM_ID(_id)                                                      \
	{                                                                      \
		.smw_id = SMW_CONFIG_HMAC_ALGO_ID_##_id,                       \
		.tee_id = TEE_ALGORITHM_ID_##_id                               \
	}

/**
 * struct - HMAC algorithm IDs
 * @smw_id: HMAC algorithm ID as defined in SMW.
 * @tee_id: HMAC algorithm ID as defined in TEE subsystem.
 */
struct {
	enum smw_config_hmac_algo_id smw_id;
	enum tee_algorithm_id tee_id;
} algorithm_ids[] = { ALGORITHM_ID(MD5),    ALGORITHM_ID(SHA1),
		      ALGORITHM_ID(SHA224), ALGORITHM_ID(SHA256),
		      ALGORITHM_ID(SHA384), ALGORITHM_ID(SHA512),
		      ALGORITHM_ID(SM3),    ALGORITHM_ID(INVALID) };

static int convert_algorithm_id(enum smw_config_hmac_algo_id smw_id,
				enum tee_algorithm_id *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i;
	unsigned int array_size = ARRAY_SIZE(algorithm_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < array_size; i++) {
		if (algorithm_ids[i].smw_id == smw_id) {
			*tee_id = algorithm_ids[i].tee_id;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * hmac() - Call TA hmac operation.
 * @args: HMAC arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int hmac(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation operation = { 0 };

	struct smw_crypto_hmac_args *hmac_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&hmac_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	uint32_t param0_type;

	struct hmac_shared_params shared_params = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!hmac_args)
		goto exit;

	status = tee_convert_key_type(key_identifier->type_id,
				      &shared_params.tee_key_type);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = convert_algorithm_id(hmac_args->algo_id,
				      &shared_params.tee_algorithm_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	/*
	 * params[0] = Key ID or Key buffer
	 * params[1] = Key type ID / HMAC algorithm ID and Security size
	 * params[2] = Message buffer and message length
	 * params[3] = MAC buffer and MAC length
	 */
	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		param0_type = TEEC_MEMREF_TEMP_INPUT;
		operation.params[0].tmpref.buffer =
			smw_keymgr_get_private_data(key_descriptor);
		operation.params[0].tmpref.size =
			smw_keymgr_get_private_length(key_descriptor);
	} else {
		param0_type = TEEC_VALUE_INPUT;
		operation.params[0].value.a = key_identifier->id;
	}
	operation.paramTypes =
		TEEC_PARAM_TYPES(param0_type, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT);

	shared_params.security_size = key_identifier->security_size;

	operation.params[1].tmpref.buffer = &shared_params;
	operation.params[1].tmpref.size = sizeof(shared_params);
	operation.params[2].tmpref.buffer = smw_hmac_get_input_data(hmac_args);
	operation.params[2].tmpref.size = smw_hmac_get_input_length(hmac_args);
	operation.params[3].tmpref.buffer = smw_hmac_get_output_data(hmac_args);
	operation.params[3].tmpref.size = smw_hmac_get_output_length(hmac_args);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_HMAC, &operation);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Operation failed\n", __func__);
		goto exit;
	}

	smw_hmac_set_output_length(hmac_args, operation.params[3].tmpref.size);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_hmac_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_HMAC:
		*status = hmac(args);
		break;
	default:
		return false;
	}

	return true;
}
