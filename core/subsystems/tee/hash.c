// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <tee_client_api.h>

#include "operations.h"
#include "subsystems.h"
#include "debug.h"
#include "utils.h"
#include "config.h"
#include "hash.h"
#include "tee.h"
#include "smw_status.h"

#define ALGORITHM_ID(_id)                                                      \
	{                                                                      \
		.smw_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                       \
		.tee_id = TEE_ALGORITHM_ID_##_id                               \
	}

/**
 * struct - Hash algorithm IDs
 * @smw_id: Hash algorithm ID as defined in SMW.
 * @tee_id: Hash algorithm ID as defined in TEE subsystem.
 */
static const struct {
	enum smw_config_hash_algo_id smw_id;
	enum tee_algorithm_id tee_id;
} algorithm_ids[] = { ALGORITHM_ID(MD5),    ALGORITHM_ID(SHA1),
		      ALGORITHM_ID(SHA224), ALGORITHM_ID(SHA256),
		      ALGORITHM_ID(SHA384), ALGORITHM_ID(SHA512),
		      ALGORITHM_ID(SM3),    ALGORITHM_ID(INVALID) };

int tee_convert_hash_algorithm_id(enum smw_config_hash_algo_id smw_id,
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
 * hash() - Call TA hash operation.
 * @args: Hash arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int hash(void *args)
{
	TEEC_Operation op = { 0 };
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_hash_args *hash_args = args;
	uint32_t tee_algorithm_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!hash_args)
		goto exit;

	/* Convert smw algorithm ID to tee algorithm ID */
	status = tee_convert_hash_algorithm_id(hash_args->algo_id,
					       &tee_algorithm_id);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s: Algorithm ID not supported\n",
			       __func__);
		goto exit;
	}

	/*
	 * params[0] = Algorithm ID
	 * params[1] = Message
	 * params[2] = Digest
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].value.a = tee_algorithm_id;
	op.params[1].tmpref.buffer = smw_crypto_get_hash_input_data(hash_args);
	op.params[1].tmpref.size = smw_crypto_get_hash_input_length(hash_args);
	op.params[2].tmpref.buffer = smw_crypto_get_hash_output_data(hash_args);
	op.params[2].tmpref.size = smw_crypto_get_hash_output_length(hash_args);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_HASH, &op);

	if (status == SMW_STATUS_OK || status == SMW_STATUS_OUTPUT_TOO_SHORT)
		smw_crypto_set_hash_output_length(hash_args,
						  op.params[2].tmpref.size);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_hash_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_HASH:
		*status = hash(args);
		break;
	default:
		return false;
	}

	return true;
}
