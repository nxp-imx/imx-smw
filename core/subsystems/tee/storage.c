// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"

#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "tee.h"
#include "storage.h"

/**
 * storage_store() - Call TA storage store operation.
 * @args: Store arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int storage_store(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	TEEC_Operation op = { 0 };
	struct smw_storage_store_data_args *store_args = args;
	struct smw_storage_data_descriptor *data_descriptor = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!store_args)
		goto exit;

	data_descriptor = &store_args->data_descriptor;

	if (store_args->enc_args.mode_id != SMW_CONFIG_CIPHER_MODE_ID_INVALID ||
	    store_args->sign_args.algo_id != SMW_CONFIG_MAC_ALGO_ID_INVALID) {
		status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
		goto exit;
	}

	/*
	 * params[0] = Object ID, persistent
	 * params[1] = Data buffer
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
				 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = smw_storage_get_data_identifier(data_descriptor);
	if (data_descriptor->attributes.persistence_id !=
	    SMW_OBJECT_PERSISTENCE_ID_TRANSIENT)
		op.params[0].value.b = 1;

	op.params[1].tmpref.buffer = smw_storage_get_data(data_descriptor);
	op.params[1].tmpref.size = smw_storage_get_data_length(data_descriptor);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_STORAGE_STORE, &op);

	store_args->data_descriptor.subsystem_id = SUBSYSTEM_ID_TEE;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * storage_retrieve() - Call TA storage retrieve operation.
 * @args: Retrieve arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int storage_retrieve(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	TEEC_Operation op = { 0 };
	struct smw_storage_retrieve_data_args *retrieve_args = args;
	struct smw_storage_data_descriptor *data_descriptor = NULL;
	unsigned int data_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!retrieve_args)
		goto exit;

	data_descriptor = &retrieve_args->data_descriptor;

	/*
	 * params[0] = Object ID, persistent
	 * params[1] = Data buffer
	 */
	op.paramTypes =
		TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
				 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = smw_storage_get_data_identifier(data_descriptor);
	if (data_descriptor->attributes.persistence_id !=
	    SMW_OBJECT_PERSISTENCE_ID_TRANSIENT)
		op.params[0].value.b = 1;

	op.params[1].tmpref.buffer = smw_storage_get_data(data_descriptor);
	op.params[1].tmpref.size = smw_storage_get_data_length(data_descriptor);

	/* Invoke TA */
	status = execute_tee_cmd(CMD_STORAGE_RETRIEVE, &op);

	if (!SET_OVERFLOW(op.params[1].tmpref.size, data_length))
		smw_storage_set_data_length(data_descriptor, data_length);
	else
		status = SMW_STATUS_OPERATION_FAILURE;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * storage_delete() - Call TA storage delete operation.
 * @args: Delete arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 * SMW_STATUS_SUBSYSTEM_FAILURE	- Operation failed.
 */
static int storage_delete(void *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	TEEC_Operation op = { 0 };
	struct smw_storage_delete_data_args *delete_args = args;
	struct smw_storage_data_descriptor *data_descriptor = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!delete_args)
		goto exit;

	data_descriptor = &delete_args->data_descriptor;

	/*
	 * params[0] = Object ID, persistent
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	op.params[0].value.a = smw_storage_get_data_identifier(data_descriptor);
	if (data_descriptor->attributes.persistence_id !=
	    SMW_OBJECT_PERSISTENCE_ID_TRANSIENT)
		op.params[0].value.b = 1;

	/* Invoke TA */
	status = execute_tee_cmd(CMD_STORAGE_DELETE, &op);

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool tee_storage_handle(enum operation_id op_id, void *args, int *status)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (op_id) {
	case OPERATION_ID_STORAGE_STORE:
		*status = storage_store(args);
		break;
	case OPERATION_ID_STORAGE_RETRIEVE:
		*status = storage_retrieve(args);
		break;
	case OPERATION_ID_STORAGE_DELETE:
		*status = storage_delete(args);
		break;
	default:
		return false;
	}

	return true;
}
