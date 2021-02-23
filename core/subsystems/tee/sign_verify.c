// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"
#include "smw_osal.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "tee_subsystem.h"
#include "tee.h"

/**
 * sign_verify() - Generate or verify a signature.
 * @args: Sign or verify arguments.
 * @op_id: OPERATION_ID_SIGN or OPERATION_ID_VERIFY.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int sign_verify(void *args, enum operation_id op_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	TEEC_Operation operation = { 0 };

	struct smw_crypto_sign_verify_args *sign_verify_args = args;
	struct smw_keymgr_descriptor *key_descriptor =
		&sign_verify_args->key_descriptor;
	struct smw_keymgr_identifier *key_identifier =
		&key_descriptor->identifier;

	uint32_t param0_type;
	uint32_t param3_type;

	uint32_t key_type_id;
	uint32_t hash_algorithm_id;

	uint32_t cmd_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!sign_verify_args)
		goto exit;

	/*
	 * params[0] = Key ID or Key buffer
	 * params[1] = Key type ID / hash algorithm ID and Security size
	 * params[2] = Message buffer and message length
	 * params[3] = Signature buffer and signature length
	 */

	switch (op_id) {
	case OPERATION_ID_SIGN:
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			/* Key buffer is only supported for verify operation */
			status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
			goto exit;
		}
		param3_type = TEEC_MEMREF_TEMP_OUTPUT;
		cmd_id = CMD_SIGN;
		break;
	case OPERATION_ID_VERIFY:
		param3_type = TEEC_MEMREF_TEMP_INPUT;
		cmd_id = CMD_VERIFY;
		break;
	default:
		goto exit;
	}

	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		param0_type = TEEC_MEMREF_TEMP_INPUT;
		operation.params[0].tmpref.buffer =
			smw_keymgr_get_public_data(key_descriptor);
		operation.params[0].tmpref.size =
			smw_keymgr_get_public_length(key_descriptor);
	} else {
		param0_type = TEEC_VALUE_INPUT;
		operation.params[0].value.a = key_identifier->id;
	}

	operation.paramTypes =
		TEEC_PARAM_TYPES(param0_type, TEEC_VALUE_INPUT,
				 TEEC_MEMREF_TEMP_INPUT, param3_type);

	status = tee_convert_key_type(key_identifier->type_id, &key_type_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	status = tee_convert_hash_algorithm_id(sign_verify_args->algo_id,
					       &hash_algorithm_id);
	if (status != SMW_STATUS_OK)
		goto exit;

	operation.params[1].value.a = (key_type_id << 16) | hash_algorithm_id;
	operation.params[1].value.b = key_identifier->security_size;
	operation.params[2].tmpref.buffer =
		smw_sign_verify_get_msg_buf(sign_verify_args);
	operation.params[2].tmpref.size =
		smw_sign_verify_get_msg_len(sign_verify_args);
	operation.params[3].tmpref.buffer =
		smw_sign_verify_get_sign_buf(sign_verify_args);
	operation.params[3].tmpref.size =
		smw_sign_verify_get_sign_len(sign_verify_args);

	/* Invoke TA */
	status = execute_tee_cmd(cmd_id, &operation);
	SMW_DBG_PRINTF_COND(ERROR, status != SMW_STATUS_OK,
			    "%s: Operation failed\n", __func__);

	if (op_id == OPERATION_ID_SIGN) {
		smw_sign_verify_set_sign_len(sign_verify_args,
					     operation.params[3].tmpref.size);

		SMW_DBG_PRINTF(DEBUG, "Output (%ld):\n",
			       operation.params[3].tmpref.size);
		SMW_DBG_HEX_DUMP(DEBUG, operation.params[3].tmpref.buffer,
				 operation.params[3].tmpref.size, 4);
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_sign_verify_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_SIGN:
	case OPERATION_ID_VERIFY:
		*status = sign_verify(args, op_id);
		break;
	default:
		return false;
	}

	return true;
}
