// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "smw_status.h"
#include "smw_keymgr.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "aead.h"

/**
 * is_aad_set() - Check if AAD length or AAD are set
 * @args: Pointer to Internal AEAD arguments structure.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid argument parameter
 */
static int is_aad_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (!smw_crypto_get_aad_len(args) || !smw_crypto_get_aad(args))
		status = SMW_STATUS_INVALID_PARAM;

	return status;
}

/**
 * is_iv_set() - Check if IV is set
 * @args: Pointer to internal AEAD arguments.
 *
 * IV and IV length must be set both GCM and CCM.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid argument parameter
 */
static int is_iv_set(struct smw_crypto_aead_args *args)
{
	if (!smw_crypto_get_iv(args) || !smw_crypto_get_iv_len(args))
		return SMW_STATUS_INVALID_PARAM;
	else
		return SMW_STATUS_OK;
}

/**
 * is_aad_len_set() - Check if AAD length is set
 * @args: Pointer to Internal AEAD arguments structure.
 *
 * AAD length must be set for CCM.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid argument parameter
 */
static int is_aad_len_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM) {
		if (!smw_crypto_get_aad_len(args))
			status = SMW_STATUS_INVALID_PARAM;
	}

	return status;
}

/**
 * is_plaintext_len_set() - Check if plaintext length is set
 * @args: Pointer to Internal AEAD arguments structure.
 *
 * Plaintext length must be set for CCM.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid configuration
 */
static int is_plaintext_len_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM) {
		if (!smw_crypto_get_plaintext_len(args))
			status = SMW_STATUS_INVALID_PARAM;
	}

	return status;
}

/**
 * is_tag_len_set() - Check if tag length is set
 * @args: Pointer to Internal AEAD arguments structure.
 *
 * tag length must be set for CCM and GCM.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid configuration
 */
static int is_tag_len_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (!smw_crypto_get_tag_len(args))
		status = SMW_STATUS_INVALID_PARAM;

	return status;
}

/**
 * aead_get_ids_from_strings() - Get config ids from strings
 * @args: Pointer to internal AEAD init arguments
 * @converted_args: Pointer to AEAD converted arguments
 * @subsystem_id: Pointer to subsystem id.
 *
 * Fields @mode_id and @op_id of @converted_args are updated.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_UNKNOWN_NAME	- Unknown name
 */
static int
aead_get_ids_from_strings(struct smw_aead_init_args *args,
			  struct smw_crypto_aead_args *converted_args,
			  enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_get_aead_mode_id(args->mode_name,
					    &converted_args->mode_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_get_aead_op_type_id(args->operation_name,
					       &converted_args->op_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_key() - Check key configuration
 * @args: Pointer to internal AEAD arguments.
 * @subsystem_id: Subsystem ID.
 *
 * This function checks that:
 * - Key is defined as buffer or as key ID
 * - Key is linked to @subsystem_id
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Bad key configuration
 */
static int check_key(struct smw_crypto_aead_args *args,
		     enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Key ID or key buffer must be set */
	if (!args->key_desc.identifier.id && !args->key_desc.pub->buffer)
		goto end;

	/*
	 * If key is defined as buffer security size and key type must
	 * be set
	 */
	if (args->key_desc.pub->buffer && (!args->key_desc.pub->type_name ||
					   !args->key_desc.pub->security_size))
		goto end;

	if (args->key_desc.identifier.id &&
	    args->key_desc.identifier.subsystem_id != subsystem_id)
		goto end;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * convert_init_args() - Convert public AEAD initialization arguments
 * @args: Pointer to public init arguments structure.
 * @converted_args: Pointer to internal AEAD arguments structure to update.
 * @subsystem_id: Pointer to subsystem ID to update.
 *
 * Return:
 * SMW_STATUS_OK				- Success
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid
 * SMW_STATUS_VERSION_NOT_SUPPORTED	- Public arguments version not supported
 * Error code from aead_get_ids_from_strings()
 * Error code from smw_keymgr_convert_descriptors()
 */
static int convert_init_args(struct smw_aead_init_args *args,
			     struct smw_crypto_aead_args *converted_args,
			     enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args->mode_name || !args->operation_name)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = aead_get_ids_from_strings(args, converted_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->init_pub = args;

	status = smw_keymgr_convert_descriptor(args->key_desc,
					       &converted_args->key_desc, false,
					       *subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead(struct smw_aead_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->data.input || !args->data.input_length ||
	    (args->data.output && !args->data.output_length))
		goto end;

	status = convert_init_args(&args->init, &aead_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	aead_args.aad = args->aad;

	if (args->data.version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = check_key(&aead_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_iv_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_aad_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_tag_len_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	aead_args.data_pub = &args->data;

	aead_args.op_step = SMW_OP_STEP_ONESHOT;

	status = smw_utils_get_aead_op_type_id(args->init.operation_name,
					       &aead_args.op_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_AEAD, &aead_args,
					     subsystem_id);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be convert to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->data.output)
		status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_init(struct smw_aead_init_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args init_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->context)
		goto end;

	status = convert_init_args(args, &init_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_key(&init_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_iv_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_aad_len_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_plaintext_len_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_tag_len_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	init_args.op_step = SMW_OP_STEP_INIT;

	status = smw_utils_execute_init(OPERATION_ID_AEAD_MULTI_PART,
					&init_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_update_add(struct smw_aead_aad_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };
	struct smw_crypto_context_ops *ops = NULL;
	struct smw_aead_data_args data_pub = { 0 };
	struct smw_aead_init_args init_pub = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->context || !args->context->handle || !args->aad ||
	    !args->aad_length)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	aead_args.data_pub = &data_pub;
	aead_args.init_pub = &init_pub;

	aead_args.op_step = SMW_OP_STEP_UPDATE;

	data_pub.context = args->context;

	aead_args.aad = args->aad;
	init_pub.aad_length = args->aad_length;

	ops = (struct smw_crypto_context_ops *)args->context->reserved;
	if (ops)
		status =
			smw_utils_execute_update_implicit(OPERATION_ID_AEAD_AAD,
							  &aead_args,
							  ops->subsystem);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_update(struct smw_aead_data_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };
	struct smw_crypto_context_ops *ops = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->context || !args->context->handle || !args->input ||
	    !args->input_length || (args->output && !args->output_length))
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	aead_args.op_step = SMW_OP_STEP_UPDATE;

	aead_args.data_pub = args;

	ops = (struct smw_crypto_context_ops *)args->context->reserved;
	if (!ops)
		goto end;

	status = smw_utils_execute_update(OPERATION_ID_AEAD_MULTI_PART,
					  &aead_args, ops->subsystem);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be converted to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->output)
		status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_final(struct smw_aead_final_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };
	struct smw_crypto_context_ops *ops = NULL;
	struct smw_aead_init_args init_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->data.context || !args->data.context->handle ||
	    (args->data.input && !args->data.input_length) ||
	    (args->data.output && !args->data.output_length))
		goto end;

	if (args->version != 0 || args->data.version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	aead_args.init_pub = &init_args;

	status = smw_utils_get_aead_op_type_id(args->operation_name,
					       &aead_args.op_id);
	if (status != SMW_STATUS_OK)
		goto end;

	aead_args.op_step = SMW_OP_STEP_FINAL;
	aead_args.data_pub = &args->data;
	aead_args.init_pub->tag_length = args->tag_length;

	ops = (struct smw_crypto_context_ops *)args->data.context->reserved;
	if (!ops)
		goto end;

	status = smw_utils_execute_final(OPERATION_ID_AEAD_MULTI_PART,
					 &aead_args, ops->subsystem);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be convert to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->data.output)
		status = SMW_STATUS_OK;

	if (aead_args.op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT)
		args->tag_length = aead_args.init_pub->tag_length;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned char *smw_crypto_get_aad(struct smw_crypto_aead_args *args)
{
	if (args)
		return args->aad;

	return NULL;
}

inline unsigned int smw_crypto_get_aad_len(struct smw_crypto_aead_args *args)
{
	if (args && args->init_pub)
		return args->init_pub->aad_length;

	return 0;
}

inline unsigned char *smw_crypto_get_iv(struct smw_crypto_aead_args *args)
{
	if (args && args->init_pub)
		return args->init_pub->iv;

	return NULL;
}

inline unsigned int smw_crypto_get_iv_len(struct smw_crypto_aead_args *args)
{
	if (args && args->init_pub)
		return args->init_pub->iv_length;

	return 0;
}

unsigned int smw_crypto_get_plaintext_len(struct smw_crypto_aead_args *args)
{
	if (args && args->init_pub)
		return args->init_pub->plaintext_length;

	return 0;
}

inline unsigned char *smw_crypto_get_input(struct smw_crypto_aead_args *args)
{
	if (args && args->data_pub)
		return args->data_pub->input;

	return NULL;
}

inline unsigned int smw_crypto_get_input_len(struct smw_crypto_aead_args *args)
{
	unsigned int input_length = 0;

	if (args && args->data_pub)
		input_length = args->data_pub->input_length;

	return input_length;
}

inline unsigned char *smw_crypto_get_output(struct smw_crypto_aead_args *args)
{
	if (args && args->data_pub)
		return args->data_pub->output;

	return NULL;
}

inline unsigned int smw_crypto_get_output_len(struct smw_crypto_aead_args *args)
{
	unsigned int output_length = 0;

	if (args && args->data_pub)
		output_length = args->data_pub->output_length;

	return output_length;
}

inline void smw_crypto_set_output_len(struct smw_crypto_aead_args *args,
				      unsigned int len)
{
	if (args && args->data_pub)
		args->data_pub->output_length = len;
}

inline unsigned char *smw_crypto_get_tag(struct smw_crypto_aead_args *args)
{
	unsigned int input_length = 0;
	unsigned int tag_length = 0;
	unsigned int output_length = 0;
	unsigned int tag_index = 0;

	if (args) {
		tag_length = smw_crypto_get_tag_len(args);

		if (args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT) {
			output_length = smw_crypto_get_output_len(args);
			tag_index = output_length;

			if (!DEC_OVERFLOW(tag_index, tag_length))
				return &args->data_pub->output[tag_index];

		} else if (args->op_id == SMW_CONFIG_AEAD_OP_ID_DECRYPT) {
			input_length = smw_crypto_get_input_len(args);
			tag_index = input_length;

			if (!DEC_OVERFLOW(tag_index, tag_length))
				return &args->data_pub->input[tag_index];
		}
	}

	return NULL;
}

inline unsigned int smw_crypto_get_tag_len(struct smw_crypto_aead_args *args)
{
	unsigned int tag_length = 0;

	if (args && args->init_pub)
		tag_length = args->init_pub->tag_length;

	return tag_length;
}

inline void smw_crypto_set_tag_len(struct smw_crypto_aead_args *args,
				   unsigned int len)
{
	if (args && args->init_pub)
		args->init_pub->tag_length = len;
}

inline void smw_crypto_set_init_op_context(struct smw_crypto_aead_args *args,
					   struct smw_op_context *op_context)
{
	if (args && args->init_pub)
		args->init_pub->context = op_context;
}

inline void smw_crypto_set_data_op_context(struct smw_crypto_aead_args *args,
					   struct smw_op_context *op_context)
{
	if (args && args->data_pub)
		args->data_pub->context = op_context;
}

inline void smw_crypto_set_init_handle(struct smw_crypto_aead_args *args,
				       void *handle)
{
	if (args && args->init_pub && args->init_pub->context)
		args->init_pub->context->handle = handle;
}

inline void *smw_crypto_get_op_handle(struct smw_crypto_aead_args *args)
{
	if (args && args->data_pub && args->data_pub->context)
		return args->data_pub->context->handle;

	return NULL;
}

inline void smw_crypto_set_ctx_reserved(struct smw_crypto_aead_args *args,
					struct smw_crypto_context_ops *rsvd)
{
	if (args && args->init_pub && args->init_pub->context)
		args->init_pub->context->reserved = rsvd;
}
