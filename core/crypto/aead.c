// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
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
 * is_iv_set() - Check if IV is set
 * @args: Pointer to internal AEAD arguments.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid argument parameter
 */
static int is_iv_set(struct smw_crypto_aead_args *args)
{
	if (!smw_crypto_get_aead_iv(args) && smw_crypto_get_aead_iv_len(args))
		return SMW_STATUS_INVALID_PARAM;
	else
		return SMW_STATUS_OK;
}

/**
 * is_plaintext_len_set() - Check if plaintext length is set
 * @args: Pointer to internal AEAD arguments structure.
 *
 * Plaintext length must be set for CCM.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid argument parameter
 */
static int is_plaintext_len_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (args->mode_id == SMW_CONFIG_AEAD_MODE_ID_CCM) {
		if (!smw_crypto_get_aead_plaintext_len(args))
			status = SMW_STATUS_INVALID_PARAM;
	}

	return status;
}

/**
 * is_tag_len_set() - Check if tag length is set
 * @args: Pointer to internal AEAD arguments structure.
 *
 * Tag length must be set for CCM and GCM.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid configuration
 */
static int is_tag_len_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (!smw_crypto_get_aead_tag_len(args))
		status = SMW_STATUS_INVALID_PARAM;

	return status;
}

/**
 * is_output_iv_set() - Check if output IV buffer is set
 * @args: Pointer to internal AEAD arguments structure.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid configuration
 */
static int is_output_iv_set(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_OK;

	if (!smw_crypto_get_aead_output_iv(args) &&
	    args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT)
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
 * SMW_STATUS_UNKNOWN_SUBSYSTEM_NAME	- Unknown subsystem name
 * SMW_STATUS_UNKNOWN_OP_TYPE_NAME	- Unknown operation type name
 * SMW_STATUS_UNKNOWN_MODE_NAME	- Unknown mode name
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

	if (converted_args->op_step == SMW_OP_STEP_INIT)
		converted_args->init_pub = args;
	else if (converted_args->op_step == SMW_OP_STEP_ONESHOT)
		converted_args->oneshot_pub->init = args;

	status = smw_keymgr_convert_descriptor(args->key_desc,
					       &converted_args->key_desc, false,
					       subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_tag_buffer() - Get AEAD tag buffer address
 * @args: Pointer to internal AEAD argument structure
 *
 * Assign the address of the dedicated tag to @args->tag field, if tag is set
 * in the dedicated tag field. Otherwise, assign the address of the tag set
 * in the following fields based on operation type.
 *  - For one-shot encryption: @args->oneshot_pub->final->data->output
 *  - For multi-part encryption: @args->final_pub->data->output
 *  - For one-shot decryption: @args->oneshot_pub->final->data->input
 *  - For multi-part decryption: @args->final_pub->data->input
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid argument parameter
 * SMW_STATUS_OUTPUT_TOO_SHORT	- Ouptut buffer is too short
 */

static int get_tag_buffer(struct smw_crypto_aead_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned int input_length = 0;
	unsigned int tag_length = 0;
	unsigned int output_length = 0;
	unsigned int tag_index = 0;
	struct smw_aead_final_args *final = NULL;

	if (!args)
		return status;

	args->tag = NULL;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			final = args->oneshot_pub->final;

		break;

	case SMW_OP_STEP_FINAL:
		final = args->final_pub;
		break;

	default:
		break;
	}

	if (!final)
		return status;

	if (final->tag) {
		args->tag = final->tag;
		return SMW_STATUS_OK;
	}

	if (!final->data)
		return status;

	tag_length = smw_crypto_get_aead_tag_len(args);

	if (args->op_id == SMW_CONFIG_AEAD_OP_ID_ENCRYPT) {
		output_length = smw_crypto_get_aead_output_len(args);
		tag_index = output_length;

		if (!DEC_OVERFLOW(tag_index, tag_length)) {
			if (final->data->output) {
				args->tag = &final->data->output[tag_index];
				status = SMW_STATUS_OK;
			}
		} else {
			status = SMW_STATUS_OUTPUT_TOO_SHORT;
		}

	} else if (args->op_id == SMW_CONFIG_AEAD_OP_ID_DECRYPT) {
		input_length = smw_crypto_get_aead_input_len(args);
		tag_index = input_length;

		if (!DEC_OVERFLOW(tag_index, tag_length)) {
			if (final->data->input) {
				args->tag = &final->data->input[tag_index];
				status = SMW_STATUS_OK;
			}
		}
	}

	return status;
}

unsigned char *smw_crypto_get_aead_aad(struct smw_crypto_aead_args *args)
{
	unsigned char *aad = NULL;

	if (!args)
		return aad;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->aad)
			aad = args->oneshot_pub->aad->data;

		break;

	/* op_step for OPERATION_ID_AEAD_UPDATE_AAD, is SMW_OP_STEP_UPDATE */
	case SMW_OP_STEP_UPDATE:
		if (args->aad_pub)
			aad = args->aad_pub->data;

		break;

	default:
		break;
	}

	return aad;
}

unsigned int smw_crypto_get_aead_aad_len(struct smw_crypto_aead_args *args)
{
	unsigned int aad_length = 0;

	if (!args)
		return aad_length;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (!args->oneshot_pub)
			return aad_length;

		/*
		 * In the public AEAD one-shot arguments structure "smw_aead_args"
		 * (args->oneshot_pub), there are two fields (aad->data_length and
		 * init->aad_length) designated to store the AAD length.
		 * Therefore, the AAD length can be retrieved from either of these
		 * two fields.
		 */
		if (args->oneshot_pub->aad &&
		    args->oneshot_pub->aad->data_length)
			aad_length = args->oneshot_pub->aad->data_length;
		else if (args->oneshot_pub->init)
			aad_length = args->oneshot_pub->init->aad_length;

		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			aad_length = args->init_pub->aad_length;

		break;

	/* op_step for OPERATION_ID_AEAD_AAD, is SMW_OP_STEP_UPDATE */
	case SMW_OP_STEP_UPDATE:
		if (args->aad_pub)
			aad_length = args->aad_pub->data_length;
		break;

	default:
		break;
	}

	return aad_length;
}

unsigned char *smw_crypto_get_aead_iv(struct smw_crypto_aead_args *args)
{
	unsigned char *iv = NULL;

	if (!args)
		return iv;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->init)
			iv = args->oneshot_pub->init->iv;

		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			iv = args->init_pub->iv;

		break;

	default:
		break;
	}

	return iv;
}

unsigned int smw_crypto_get_aead_iv_len(struct smw_crypto_aead_args *args)
{
	unsigned int iv_length = 0;

	if (!args)
		return iv_length;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->init)
			iv_length = args->oneshot_pub->init->iv_length;

		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			iv_length = args->init_pub->iv_length;

		break;

	default:
		break;
	}

	return iv_length;
}

unsigned char *smw_crypto_get_aead_output_iv(struct smw_crypto_aead_args *args)
{
	unsigned char *output_iv = NULL;

	if (!args)
		return output_iv;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final)
			output_iv = args->oneshot_pub->final->output_iv;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			output_iv = args->final_pub->output_iv;

		break;

	default:
		break;
	}

	return output_iv;
}

unsigned int
smw_crypto_get_aead_output_iv_len(struct smw_crypto_aead_args *args)
{
	unsigned int output_iv_len = 0;

	if (!args)
		return output_iv_len;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final)
			output_iv_len =
				args->oneshot_pub->final->output_iv_length;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			output_iv_len = args->final_pub->output_iv_length;

		break;

	default:
		break;
	}

	return output_iv_len;
}

unsigned int
smw_crypto_get_aead_plaintext_len(struct smw_crypto_aead_args *args)
{
	unsigned int plaintext_length = 0;

	if (!args)
		return plaintext_length;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->init)
			plaintext_length =
				args->oneshot_pub->init->plaintext_length;

		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			plaintext_length = args->init_pub->plaintext_length;

		break;

	default:
		break;
	}

	return plaintext_length;
}

unsigned char *smw_crypto_get_aead_input(struct smw_crypto_aead_args *args)
{
	unsigned char *input = NULL;

	if (!args)
		return input;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final &&
		    args->oneshot_pub->final->data)
			input = args->oneshot_pub->final->data->input;

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->data_pub)
			input = args->data_pub->input;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->data)
			input = args->final_pub->data->input;

		break;

	default:
		break;
	}

	return input;
}

unsigned int smw_crypto_get_aead_input_len(struct smw_crypto_aead_args *args)
{
	unsigned int input_length = 0;

	if (!args)
		return input_length;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final &&
		    args->oneshot_pub->final->data)
			input_length =
				args->oneshot_pub->final->data->input_length;

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->data_pub)
			input_length = args->data_pub->input_length;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->data)
			input_length = args->final_pub->data->input_length;

		break;

	default:
		break;
	}

	return input_length;
}

unsigned char *smw_crypto_get_aead_output(struct smw_crypto_aead_args *args)
{
	unsigned char *output = NULL;

	if (!args)
		return output;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final &&
		    args->oneshot_pub->final->data)
			output = args->oneshot_pub->final->data->output;

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->data_pub)
			output = args->data_pub->output;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->data)
			output = args->final_pub->data->output;

		break;

	default:
		break;
	}

	return output;
}

unsigned int smw_crypto_get_aead_output_len(struct smw_crypto_aead_args *args)
{
	unsigned int output_length = 0;

	if (!args)
		return output_length;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final &&
		    args->oneshot_pub->final->data)
			output_length =
				args->oneshot_pub->final->data->output_length;

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->data_pub)
			output_length = args->data_pub->output_length;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->data)
			output_length = args->final_pub->data->output_length;

		break;

	default:
		break;
	}

	return output_length;
}

void smw_crypto_set_aead_output_len(struct smw_crypto_aead_args *args,
				    unsigned int len)
{
	if (!args)
		return;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final &&
		    args->oneshot_pub->final->data)
			args->oneshot_pub->final->data->output_length = len;

		break;

	case SMW_OP_STEP_UPDATE:
		if (args->data_pub)
			args->data_pub->output_length = len;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->data)
			args->final_pub->data->output_length = len;

		break;

	default:
		break;
	}
}

inline unsigned char *smw_crypto_get_aead_tag(struct smw_crypto_aead_args *args)
{
	if (args && args->tag)
		return args->tag;
	else
		return NULL;
}

bool smw_crypto_is_aead_tag_field_set(struct smw_crypto_aead_args *args)
{
	bool status = false;

	if (!args)
		return status;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final &&
		    args->oneshot_pub->final->tag)
			status = true;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->tag)
			status = true;

		break;

	default:
		break;
	}

	return status;
}

unsigned int smw_crypto_get_aead_tag_len(struct smw_crypto_aead_args *args)
{
	unsigned int tag_length = 0;

	if (!args)
		return tag_length;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (!args->oneshot_pub)
			return tag_length;

		/*
		 * In the public AEAD one-shot arguments structure "smw_aead_args"
		 * (args->oneshot_pub), there are two fields (final->tag_length and
		 * init->tag_length) designated to store the tag length.
		 * Therefore, the tag length can be retrieved from either of these
		 * two fields.
		 */
		if (args->oneshot_pub->final &&
		    args->oneshot_pub->final->tag_length)
			tag_length = args->oneshot_pub->final->tag_length;
		else if (args->oneshot_pub->init)
			tag_length = args->oneshot_pub->init->tag_length;

		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			tag_length = args->init_pub->tag_length;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			tag_length = args->final_pub->tag_length;

		break;

	default:
		break;
	}

	return tag_length;
}

void smw_crypto_set_aead_tag_len(struct smw_crypto_aead_args *args,
				 unsigned int len)
{
	if (!args)
		return;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final)
			args->oneshot_pub->final->tag_length = len;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			args->final_pub->tag_length = len;

		break;

	default:
		break;
	}
}

inline void smw_crypto_set_aead_output_iv_len(struct smw_crypto_aead_args *args,
					      unsigned int len)
{
	if (!args)
		return;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->final)
			args->oneshot_pub->final->output_iv_length = len;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			args->final_pub->output_iv_length = len;

		break;

	default:
		break;
	}
}

struct smw_op_context *
smw_crypto_get_aead_init_op_context(struct smw_crypto_aead_args *args)
{
	struct smw_op_context *ctx = NULL;

	if (!args)
		return ctx;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub && args->oneshot_pub->init)
			ctx = args->oneshot_pub->init->context;

		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			ctx = args->init_pub->context;

		break;

	default:
		break;
	}

	return ctx;
}

struct smw_op_context *
smw_crypto_get_aead_data_op_context(struct smw_crypto_aead_args *args)
{
	struct smw_op_context *ctx = NULL;

	if (!args)
		return ctx;

	switch (args->op_step) {
	case SMW_OP_STEP_UPDATE:
		if (args->data_pub)
			ctx = args->data_pub->context;

		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub && args->final_pub->data)
			ctx = args->final_pub->data->context;

		break;

	default:
		break;
	}

	return ctx;
}

inline struct smw_op_context *
smw_crypto_get_aead_aad_op_context(struct smw_crypto_aead_args *args)
{
	void *ctx = NULL;

	if (args && args->op_step == SMW_OP_STEP_UPDATE && args->aad_pub)
		ctx = args->aad_pub->context;

	return ctx;
}

enum smw_status_code smw_aead(struct smw_aead_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->init || !args->final || !args->final->data ||
	    !args->final->data->input || !args->final->data->input_length ||
	    (args->final->data->output && !args->final->data->output_length))
		goto end;

	aead_args.oneshot_pub = args;

	aead_args.op_step = SMW_OP_STEP_ONESHOT;

	status = convert_init_args(args->init, &aead_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->final->version != 0 || args->final->data->version != 0 ||
	    (args->aad && args->aad->version != 0)) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = check_key(&aead_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_iv_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_output_iv_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_tag_len_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tag_buffer(&aead_args);
	/*
	 * In order to fetch the required output length, tag length and output iv
	 * length, the code flow should continue even if get_tag_buffer() returns
	 * SMW_STATUS_OUTPUT_TOO_SHORT.
	 */
	if (status == SMW_STATUS_INVALID_PARAM)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_AEAD, &aead_args,
					     subsystem_id);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be convert to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->final->data->output)
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

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context)
		goto end;

	init_args.op_step = SMW_OP_STEP_INIT;

	status = convert_init_args(args, &init_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_key(&init_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_iv_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_plaintext_len_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_tag_len_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_init(OPERATION_ID_AEAD_MULTI_PART,
					&init_args, subsystem_id);
	/*
	 * Release the context if the init operation has returned any status
	 * code except SMW_STATUS_OK and SMW_STATUS_INVALID_PARAM.
	 */
	if (status != SMW_STATUS_OK && status != SMW_STATUS_INVALID_PARAM)
		(void)smw_utils_free_context(&args->context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_update_aad(struct smw_aead_aad_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context || !args->data || !args->data_length)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	aead_args.op_step = SMW_OP_STEP_UPDATE;

	aead_args.aad_pub = args;

	status = smw_utils_execute_update_implicit(OPERATION_ID_AEAD_UPDATE_AAD,
						   &aead_args,
						   args->context->subsystem_id);
	/*
	 * Release the context if the update AAD operation has returned any status
	 * code except SMW_STATUS_OK and SMW_STATUS_INVALID_PARAM.
	 */
	if (status != SMW_STATUS_OK && status != SMW_STATUS_INVALID_PARAM)
		(void)smw_utils_free_context(&args->context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_update(struct smw_aead_data_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context || !args->input || !args->input_length ||
	    (args->output && !args->output_length))
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	aead_args.op_step = SMW_OP_STEP_UPDATE;
	aead_args.data_pub = args;

	status = smw_utils_execute_update(OPERATION_ID_AEAD_MULTI_PART,
					  &aead_args,
					  args->context->subsystem_id);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be converted to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->output)
		status = SMW_STATUS_OK;

	/*
	 * Release the context if the update operation has returned any status
	 * code except SMW_STATUS_OK, SMW_STATUS_OUTPUT_TOO_SHORT and
	 * SMW_STATUS_INVALID_PARAM.
	 */
	if (status != SMW_STATUS_OK && status != SMW_STATUS_OUTPUT_TOO_SHORT &&
	    status != SMW_STATUS_INVALID_PARAM)
		(void)smw_utils_free_context(&args->context);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_aead_final(struct smw_aead_final_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_aead_args aead_args = { 0 };

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data || !args->data->context ||
	    (args->data->input && !args->data->input_length) ||
	    (args->data->output && !args->data->output_length) ||
	    !args->tag_length)
		goto end;

	if (args->version != 0 || args->data->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	aead_args.op_step = SMW_OP_STEP_FINAL;

	status = smw_utils_get_aead_op_type_id(args->operation_name,
					       &aead_args.op_id);
	if (status != SMW_STATUS_OK)
		goto end;

	aead_args.final_pub = args;

	status = is_output_iv_set(&aead_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = get_tag_buffer(&aead_args);
	/*
	 * In order to fetch the required output length and tag length, the code
	 * flow should continue even if get_tag_buffer() returns
	 * SMW_STATUS_OUTPUT_TOO_SHORT.
	 */
	if (status == SMW_STATUS_INVALID_PARAM)
		goto end;

	status = smw_utils_execute_final(OPERATION_ID_AEAD_MULTI_PART,
					 &aead_args,
					 args->data->context->subsystem_id);

	/*
	 * Release the operation context if the final operation has returned any
	 * status code except SMW_STATUS_OUTPUT_TOO_SHORT and
	 * SMW_STATUS_INVALID_PARAM.
	 */
	if (status != SMW_STATUS_OUTPUT_TOO_SHORT &&
	    status != SMW_STATUS_INVALID_PARAM)
		smw_utils_free_context(&args->data->context);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be convert to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->data->output)
		status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
