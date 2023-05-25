// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include "smw_status.h"
#include "smw_keymgr.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "cipher.h"

/**
 * free_keys_ptr_array() - Free the array of keymgr descriptors pointer
 * @keys_desc: Pointer to the array to free.
 * @nb_keys: Number of entries of @keys_desc.
 *
 * Return:
 * none
 */
static void free_keys_ptr_array(struct smw_keymgr_descriptor **keys_desc,
				unsigned int nb_keys)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < nb_keys; i++) {
		if (keys_desc[i])
			SMW_UTILS_FREE(keys_desc[i]);
	}

	SMW_UTILS_FREE(keys_desc);
}

/**
 * cipher_get_ids_from_strings() - Get config ids from strings
 * @args: Pointer to SMW API cipher initialization arguments.
 * @converted_args: Pointer to cipher converted arguments to update.
 * @subsystem_id: Pointer to subsystem id to update.
 *
 * Fields @mode_id and @op_id of @converted_args are updated.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_UNKNOWN_NAME	- Unknown name
 */
static int
cipher_get_ids_from_strings(struct smw_cipher_init_args *args,
			    struct smw_crypto_cipher_args *converted_args,
			    enum subsystem_id *subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_get_cipher_mode_id(args->mode_name,
					       &converted_args->mode_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_get_cipher_op_type_id(args->operation_name,
						  &converted_args->op_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * convert_key_descriptors() - Convert public key descriptors pointer array
 *                             in internal key descriptors pointer array
 * @keys_desc: Pointer to the array of public key descriptors pointer to
 *             convert.
 * @converted_args: Pointer to cipher converted arguments to update.
 * @subsystem_id: Pointer to subsystem ID.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failure
 * Error code from smw_keymgr_convert_descriptor()
 */
static int
convert_key_descriptors(struct smw_key_descriptor **keys_desc,
			struct smw_crypto_cipher_args *converted_args,
			enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_ALLOC_FAILURE;
	unsigned int i = 0;
	struct smw_keymgr_descriptor **keymgr_desc = NULL;
	struct smw_key_descriptor *key = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * This memory is freed at the end of cipher one-shot operation or
	 * cipher initialization
	 */
	keymgr_desc = SMW_UTILS_CALLOC(converted_args->nb_keys,
				       sizeof(struct smw_keymgr_descriptor *));
	if (!keymgr_desc)
		goto end;

	for (; i < converted_args->nb_keys; i++) {
		key = keys_desc[i];

		/*
		 * This memory is freed at the end of one shot operation or
		 * cipher initialization
		 */
		keymgr_desc[i] =
			SMW_UTILS_CALLOC(1,
					 sizeof(struct smw_keymgr_descriptor));
		if (!keymgr_desc[i]) {
			status = SMW_STATUS_ALLOC_FAILURE;
			free_keys_ptr_array(keymgr_desc,
					    converted_args->nb_keys);
			goto end;
		}

		status = smw_keymgr_convert_descriptor(key, keymgr_desc[i],
						       false, *subsystem_id);
		if (status != SMW_STATUS_OK) {
			free_keys_ptr_array(keymgr_desc,
					    converted_args->nb_keys);
			goto end;
		}

		/*
		 * If @args->subsystem_name is not set and a key ID is set, get
		 * subsystem ID from key ID
		 */
		if (*subsystem_id == SUBSYSTEM_ID_INVALID && key->id)
			*subsystem_id = keymgr_desc[i]->identifier.subsystem_id;
	}

	converted_args->keys_desc = keymgr_desc;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * convert_init_args() - Convert public cipher initialization arguments
 * @args: Pointer to public arguments.
 * @converted_args: Pointer to internal argument structure to update.
 * @subsystem_id: Pointer to subsystem ID to update.
 *
 * Return:
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid
 * SMW_STATUS_VERSION_NOT_SUPPORTED	- Public arguments version not supported
 * Error code from cipher_get_ids_from_strings()
 * Error code from convert_key_descriptors()
 */
static int convert_init_args(struct smw_cipher_init_args *args,
			     struct smw_crypto_cipher_args *converted_args,
			     enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args->keys_desc || !args->nb_keys || !args->mode_name ||
	    !args->operation_name)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status =
		cipher_get_ids_from_strings(args, converted_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->nb_keys = args->nb_keys;
	converted_args->init_pub = args;

	status = convert_key_descriptors(args->keys_desc, converted_args,
					 subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * check_keys() - Check keys configuration
 * @args: Pointer to internal cipher arguments.
 * @subsystem_id: Subsystem ID.
 *
 * This function checks that:
 * - Keys are defined as buffer or as key ID
 * - Keys are linked to @subsystem_id
 * - Keys type are identical
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Bad keys configuration
 */
static int check_keys(struct smw_crypto_cipher_args *args,
		      enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int i;
	enum smw_config_key_type_id key_type;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Check number of keys switch cipher mode */
	switch (args->mode_id) {
	case SMW_CONFIG_CIPHER_MODE_ID_XTS:
		if (args->nb_keys != 2)
			goto end;

		break;

	default:
		if (args->nb_keys != 1)
			goto end;

		break;
	}

	key_type = args->keys_desc[0]->identifier.type_id;

	for (i = 0; i < args->nb_keys; i++) {
		/* Key ID or key buffer must be set */
		if (!args->keys_desc[i]->identifier.id &&
		    !args->keys_desc[i]->pub->buffer)
			goto end;

		/*
		 * If key is defined as buffer security size and key type must
		 * be set
		 */
		if (args->keys_desc[i]->pub->buffer &&
		    (!args->keys_desc[i]->pub->type_name ||
		     !args->keys_desc[i]->pub->security_size))
			goto end;

		/* Subsystem must be the same for all keys */
		if (args->keys_desc[i]->identifier.id &&
		    args->keys_desc[i]->identifier.subsystem_id != subsystem_id)
			goto end;

		/* Key type must be the same for all keys */
		if (key_type != args->keys_desc[i]->identifier.type_id)
			goto end;
	}

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * is_iv_set() - Check if IV is set
 * @args: Pointer to internal cipher arguments.
 *
 * IV and IV length must be set for all cipher modes except ECB.
 *
 * Return:
 * SMW_STATUS_OK		- Success
 * SMW_STATUS_INVALID_PARAM	- Invalid configuration
 */
static int is_iv_set(struct smw_crypto_cipher_args *args)
{
	switch (args->mode_id) {
	case SMW_CONFIG_CIPHER_MODE_ID_ECB:
		break;

	default:
		if (!smw_crypto_get_cipher_iv(args) ||
		    !smw_crypto_get_cipher_iv_len(args))
			return SMW_STATUS_INVALID_PARAM;

		break;
	}

	return SMW_STATUS_OK;
}

enum smw_status_code smw_cipher(struct smw_cipher_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_cipher_args cipher_args = { 0 };
	enum subsystem_id subsystem_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->data.input || !args->data.input_length ||
	    (args->data.output && !args->data.output_length))
		goto end;

	status = convert_init_args(&args->init, &cipher_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (args->data.version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	cipher_args.data_pub = &args->data;

	status = check_keys(&cipher_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_iv_set(&cipher_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_CIPHER, &cipher_args,
					     subsystem_id);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be convert to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->data.output)
		status = SMW_STATUS_OK;

end:
	/* Free keys decriptor allocated in one_shot_convert_args() */
	if (cipher_args.keys_desc)
		free_keys_ptr_array(cipher_args.keys_desc, cipher_args.nb_keys);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_cipher_init(struct smw_cipher_init_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_cipher_args init_args = { 0 };
	enum subsystem_id subsystem_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->context)
		goto end;

	status = convert_init_args(args, &init_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = check_keys(&init_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = is_iv_set(&init_args);
	if (status != SMW_STATUS_OK)
		goto end;

	init_args.op_step = SMW_OP_STEP_INIT;

	status = smw_utils_execute_init(OPERATION_ID_CIPHER_MULTI_PART,
					&init_args, subsystem_id);

end:
	/* Free keys decriptor allocated in convert_init_args() */
	if (init_args.keys_desc)
		free_keys_ptr_array(init_args.keys_desc, init_args.nb_keys);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_cipher_update(struct smw_cipher_data_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_cipher_args update_args = { 0 };
	struct smw_crypto_context_ops *ops;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->context || !args->context->handle || !args->input ||
	    !args->input_length || !args->output || !args->output_length)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	update_args.op_step = SMW_OP_STEP_UPDATE;
	update_args.data_pub = args;

	ops = (struct smw_crypto_context_ops *)args->context->reserved;

	status = smw_utils_execute_update(OPERATION_ID_CIPHER_MULTI_PART,
					  &update_args, ops->subsystem);

end:

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_cipher_final(struct smw_cipher_data_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_cipher_args final_args = { 0 };
	struct smw_crypto_context_ops *ops;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->context || !args->context->handle ||
	    (args->input && !args->input_length) ||
	    (args->output && !args->output_length))
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	final_args.op_step = SMW_OP_STEP_FINAL;
	final_args.data_pub = args;

	ops = (struct smw_crypto_context_ops *)args->context->reserved;

	status = smw_utils_execute_final(OPERATION_ID_CIPHER_MULTI_PART,
					 &final_args, ops->subsystem);

	/*
	 * SMW_STATUS_OUTPUT_TOO_SHORT is the expected internal status if the
	 * 'get output buffer length' feature succeed and must be convert to
	 * SMW_STATUS_OK
	 */
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->output)
		status = SMW_STATUS_OK;

end:

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned char *
smw_crypto_get_cipher_iv(struct smw_crypto_cipher_args *args)
{
	if (args && args->init_pub)
		return args->init_pub->iv;

	return NULL;
}

inline unsigned int
smw_crypto_get_cipher_iv_len(struct smw_crypto_cipher_args *args)
{
	if (args && args->init_pub)
		return args->init_pub->iv_length;

	return 0;
}

inline uint32_t
smw_crypto_get_cipher_key_id(struct smw_crypto_cipher_args *args,
			     unsigned int idx)
{
	if (args)
		return args->keys_desc[idx]->identifier.id;

	return 0;
}

inline unsigned char *
smw_crypto_get_cipher_input(struct smw_crypto_cipher_args *args)
{
	if (args && args->data_pub)
		return args->data_pub->input;

	return NULL;
}

inline unsigned int
smw_crypto_get_cipher_input_len(struct smw_crypto_cipher_args *args)
{
	if (args && args->data_pub)
		return args->data_pub->input_length;

	return 0;
}

inline unsigned char *
smw_crypto_get_cipher_output(struct smw_crypto_cipher_args *args)
{
	if (args && args->data_pub)
		return args->data_pub->output;

	return NULL;
}

inline unsigned int
smw_crypto_get_cipher_output_len(struct smw_crypto_cipher_args *args)
{
	if (args && args->data_pub)
		return args->data_pub->output_length;

	return 0;
}

inline void *
smw_crypto_get_cipher_op_handle(struct smw_crypto_cipher_args *args)
{
	if (args && args->data_pub && args->data_pub->context)
		return args->data_pub->context->handle;

	return NULL;
}

inline void
smw_crypto_set_cipher_output_len(struct smw_crypto_cipher_args *args,
				 unsigned int len)
{
	if (args && args->data_pub)
		args->data_pub->output_length = len;
}

inline void
smw_crypto_set_cipher_data_op_context(struct smw_crypto_cipher_args *args,
				      struct smw_op_context *op_context)
{
	if (args && args->data_pub)
		args->data_pub->context = op_context;
}

inline void
smw_crypto_set_cipher_init_op_context(struct smw_crypto_cipher_args *args,
				      struct smw_op_context *op_context)
{
	if (args && args->init_pub)
		args->init_pub->context = op_context;
}

inline void
smw_crypto_set_cipher_ctx_reserved(struct smw_crypto_cipher_args *args,
				   struct smw_crypto_context_ops *rsvd)
{
	if (args && args->init_pub && args->init_pub->context)
		args->init_pub->context->reserved = rsvd;
}

inline void
smw_crypto_set_cipher_init_handle(struct smw_crypto_cipher_args *args,
				  void *handle)
{
	if (args && args->init_pub && args->init_pub->context)
		args->init_pub->context->handle = handle;
}

unsigned int
smw_crypto_get_cipher_nb_key_buffer(struct smw_crypto_cipher_args *args)
{
	unsigned int i;
	unsigned int nb_buffers = 0;

	/* Key is defined as buffer if ID is not set and buffer set */
	for (i = 0; i < args->nb_keys; i++) {
		if (!args->keys_desc[i]->identifier.id &&
		    smw_keymgr_get_private_data(args->keys_desc[i]))
			nb_buffers++;
	}

	return nb_buffers;
}
