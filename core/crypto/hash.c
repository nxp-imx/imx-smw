// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2026 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "hash.h"
#include "exec.h"

/**
 * struct hash_init_args_v0 - Hash multi-part initialization arguments V0
 * @version: Version of this structure (must be set to 0)
 * @algo_name: Algorithm name. See &typedef smw_hash_algo_t
 * @input: Location of the stream to be hashed
 * @input_length: Length of the stream to be hashed
 * @context: Pointer to an opaque operation context structure
 *
 * This structure is defined to be backward compatible with version 0
 * of hash initialization arguments.
 */
struct hash_init_args_v0 {
	/* Inputs */
	unsigned char version;
	smw_hash_algo_t algo_name;
	unsigned char *input;
	unsigned int input_length;
	/* Outputs */
	struct smw_op_context *context;
};

static int convert_args(struct smw_hash_args *args,
			struct smw_crypto_hash_args *converted_args,
			enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	converted_args->op_step = SMW_OP_STEP_ONESHOT;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_get_hash_algo_id(args->algo_name,
					    &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->oneshot_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int convert_init_args(struct smw_hash_init_args *args,
			     struct smw_crypto_hash_args *converted_args,
			     enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	struct hash_init_args_v0 *args_v0 = (struct hash_init_args_v0 *)args;
	smw_hash_algo_t algo_name = SMW_HASH_ALGO_NAME_NONE;
	struct smw_op_context *ctx = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version > 1) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	if (args->version == 0) {
		if (!args_v0->context ||
		    !args_v0->input != !args_v0->input_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		algo_name = args_v0->algo_name;
		*subsystem_id = args_v0->context->subsystem_id;
		ctx = args_v0->context;
	} else {
		if (!args->context || !args->input != !args->input_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		algo_name = args->algo_name;
		ctx = args->context;
	}

	if (ctx->op_state != CTX_OP_STATE_ALLOC) {
		status = SMW_STATUS_OPERATION_ALREADY_INIT;
		goto end;
	}

	converted_args->op_step = SMW_OP_STEP_INIT;

	status =
		smw_utils_get_hash_algo_id(algo_name, &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->version != 0) {
		status = smw_config_get_subsystem_id(args->subsystem_name,
						     subsystem_id);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	converted_args->init_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int convert_update_args(struct smw_hash_update_args *args,
			       struct smw_crypto_hash_args *converted_args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	converted_args->op_step = SMW_OP_STEP_UPDATE;

	converted_args->update_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int convert_final_args(struct smw_hash_final_args *args,
			      struct smw_crypto_hash_args *converted_args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	converted_args->op_step = SMW_OP_STEP_FINAL;

	converted_args->final_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

unsigned char *smw_crypto_get_hash_input_data(struct smw_crypto_hash_args *args)
{
	unsigned char *input_data = NULL;
	struct hash_init_args_v0 *args_v0 = NULL;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			input_data = args->oneshot_pub->input;
		break;

	case SMW_OP_STEP_INIT:
		if (!args->init_pub)
			break;

		if (args->init_pub->version == 0) {
			args_v0 = (struct hash_init_args_v0 *)args->init_pub;
			input_data = args_v0->input;
		} else {
			input_data = args->init_pub->input;
		}

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->update_pub)
			input_data = args->update_pub->input;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			input_data = args->final_pub->input;
		break;

	default:
		break;
	}

	return input_data;
}

unsigned int smw_crypto_get_hash_input_length(struct smw_crypto_hash_args *args)
{
	unsigned int input_length = 0;
	struct hash_init_args_v0 *args_v0 = NULL;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			input_length = args->oneshot_pub->input_length;
		break;

	case SMW_OP_STEP_INIT:
		if (!args->init_pub)
			break;

		if (args->init_pub->version == 0) {
			args_v0 = (struct hash_init_args_v0 *)args->init_pub;
			input_length = args_v0->input_length;
		} else {
			input_length = args->init_pub->input_length;
		}

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->update_pub)
			input_length = args->update_pub->input_length;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			input_length = args->final_pub->input_length;
		break;

	default:
		break;
	}

	return input_length;
}

unsigned char *
smw_crypto_get_hash_output_data(struct smw_crypto_hash_args *args)
{
	unsigned char *output_data = NULL;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			output_data = args->oneshot_pub->output;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			output_data = args->final_pub->output;
		break;

	default:
		break;
	}

	return output_data;
}

unsigned int
smw_crypto_get_hash_output_length(struct smw_crypto_hash_args *args)
{
	unsigned int output_length = 0;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			output_length = args->oneshot_pub->output_length;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			output_length = args->final_pub->output_length;
		break;

	default:
		break;
	}

	return output_length;
}

void smw_crypto_set_hash_output_length(struct smw_crypto_hash_args *args,
				       unsigned int output_length)
{
	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			args->oneshot_pub->output_length = output_length;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			args->final_pub->output_length = output_length;
		break;

	default:
		break;
	}
}

struct smw_op_context *
smw_crypto_get_hash_op_context(struct smw_crypto_hash_args *args)
{
	struct smw_op_context *ctx = NULL;
	struct hash_init_args_v0 *args_v0 = NULL;

	if (!args)
		return ctx;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		if (!args->init_pub)
			break;

		if (args->init_pub->version == 0) {
			args_v0 = (struct hash_init_args_v0 *)args->init_pub;
			ctx = args_v0->context;
		} else {
			ctx = args->init_pub->context;
		}

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->update_pub)
			ctx = args->update_pub->context;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			ctx = args->final_pub->context;

		break;

	default:
		break;
	}

	return ctx;
}

enum smw_status_code smw_hash(struct smw_hash_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_hash_args hash_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args)
		goto end;

	if ((!args->input != !args->input_length) ||
	    (!args->output != !args->output_length))
		goto end;

	status = convert_args(args, &hash_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_HASH, &hash_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_hash_init(struct smw_hash_init_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_hash_args hash_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_op_context *context = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args)
		goto end;

	status = convert_init_args(args, &hash_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_init(OPERATION_ID_HASH_MULTI_PART,
					&hash_args, subsystem_id);
	/*
	 * Release the context if the init operation has returned any status
	 * code except SMW_STATUS_OK and SMW_STATUS_INVALID_PARAM.
	 */
	if (status != SMW_STATUS_OK && status != SMW_STATUS_INVALID_PARAM) {
		context = smw_crypto_get_hash_op_context(&hash_args);
		if (context)
			(void)smw_utils_free_context(&context);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_hash_update(struct smw_hash_update_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_hash_args hash_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context || !args->input || !args->input_length)
		goto end;

	status = convert_update_args(args, &hash_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_crypto_get_ctx_subsystem_id(args->context, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_update(OPERATION_ID_HASH_MULTI_PART,
					  &hash_args, subsystem_id);

	/*
	 * Release the operation context if the final operation has returned any
	 * status code except SMW_STATUS_OK and SMW_STATUS_INVALID_PARAM.
	 */
	if (status != SMW_STATUS_OK && status != SMW_STATUS_INVALID_PARAM)
		(void)smw_utils_free_context(&args->context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_hash_final(struct smw_hash_final_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;
	struct smw_crypto_hash_args hash_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context)
		goto end;

	if ((!args->input != !args->input_length) ||
	    (!args->output != !args->output_length))
		goto end;

	status = convert_final_args(args, &hash_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_crypto_get_ctx_subsystem_id(args->context, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_final(OPERATION_ID_HASH_MULTI_PART,
					 &hash_args, subsystem_id);

	/*
	 * Get output buffer length feature - If the output buffer is NULL and
	 * subsystem returns SMW_STATUS_OUTPUT_TOO_SHORT, update the status to
	 * SMW_STATUS_OK.
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->output)
		status = SMW_STATUS_OK;

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT ||
	    status == SMW_STATUS_INVALID_PARAM ||
	    (status == SMW_STATUS_OK && !args->output))
		goto end;

	tmp_status = smw_utils_free_context(&args->context);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
