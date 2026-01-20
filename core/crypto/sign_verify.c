// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2026 NXP
 */

#include <inttypes.h>

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "sign_verify.h"
#include "exec.h"

static int
sign_verify_convert_attributes(smw_attr_algo_t in,
			       struct smw_sign_verify_attributes *out)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(DEBUG, "Signature attributes: 0x%" PRIx64 "\n", in);

	if (SMW_ATTR_GET_CLASS(in) != SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE)
		goto end;

	status = smw_utils_sign_attr_to_ids(in, &out->algo_id, &out->type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_hash_attr_to_algo_id(in, &out->hash_id);
	if (status != SMW_STATUS_OK)
		goto end;

	switch (out->algo_id) {
	case SMW_CONFIG_SIGN_ALGO_ID_RSA:
		if (SET_OVERFLOW(SMW_ATTR_GET_SALT_LENGTH(in),
				 out->salt_length))
			status = SMW_STATUS_INVALID_PARAM;

		break;

	default:
		break;
	}

	out->msg_hashed = SMW_ATTR_IS_MSG_HASHED(in);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
sign_verify_convert_args(struct smw_sign_verify_args *args,
			 struct smw_crypto_sign_verify_args *conv_args,
			 enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	bool new_key = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	conv_args->op_step = SMW_OP_STEP_ONESHOT;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &conv_args->key_descriptor,
					       &new_key, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = sign_verify_convert_attributes(args->sign_algo,
						&conv_args->attributes);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_args->oneshot_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
sign_verify_init_convert_args(struct smw_sign_verify_init_args *args,
			      struct smw_crypto_sign_verify_args *conv_args,
			      enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	bool new_key = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	conv_args->op_step = SMW_OP_STEP_INIT;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &conv_args->key_descriptor,
					       &new_key, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = sign_verify_convert_attributes(args->sign_algo,
						&conv_args->attributes);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_args->init_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
sign_verify_update_convert_args(struct smw_sign_verify_update_args *args,
				struct smw_crypto_sign_verify_args *conv_args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	conv_args->op_step = SMW_OP_STEP_UPDATE;

	conv_args->update_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
sign_verify_final_convert_args(struct smw_sign_verify_final_args *args,
			       struct smw_crypto_sign_verify_args *conv_args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	conv_args->op_step = SMW_OP_STEP_FINAL;

	conv_args->final_pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static unsigned int get_sign_size(struct smw_keymgr_descriptor *key)
{
	unsigned int size = 0;

	switch (key->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_SECP_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ED25519:
		/* Signature size is public key size */
		size = key->identifier.security_size;

		if (MUL_OVERFLOW(BITS_TO_BYTES_SIZE(size), 2, &size))
			size = 0;

		break;

	case SMW_CONFIG_KEY_TYPE_ID_ED448:
		size = key->identifier.security_size;

		if (ADD_OVERFLOW(BITS_TO_BYTES_SIZE(size), 1, &size))
			size = 0;

		if (MUL_OVERFLOW(size, 2, &size))
			size = 0;

		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		/* Signature size is modulus size */
		size = key->identifier.security_size;
		size = BITS_TO_BYTES_SIZE(size);
		break;

	case SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER:
		size = TLS12_MAC_FINISH_DEFAULT_LEN;
		break;

	default:
		break;
	}

	return size;
}

static int sign_verify(enum operation_id operation_id,
		       struct smw_sign_verify_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_crypto_sign_verify_args sign_verify_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_descriptor = NULL;
	unsigned char *public_data = NULL;
	unsigned int public_length = 0;
	unsigned char *private_data = NULL;
	unsigned int private_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * Sign API can be called with a NULL signature pointer to get the
	 * signature length
	 */
	if (!args)
		goto end;

	if (!args->message != !args->message_length)
		goto end;

	if (!args->signature != !args->signature_length)
		goto end;

	if (operation_id == OPERATION_ID_VERIFY && !args->signature)
		goto end;

	if (args->signature && !args->message)
		goto end;

	status = sign_verify_convert_args(args, &sign_verify_args,
					  &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor = &sign_verify_args.key_descriptor;

	if (!args->signature) {
		smw_sign_verify_set_sign_len(&sign_verify_args,
					     get_sign_size(key_descriptor));
		goto end;
	}

	if (operation_id == OPERATION_ID_VERIFY) {
		if (args->signature_length != get_sign_size(key_descriptor)) {
			status = SMW_STATUS_SIGNATURE_LEN_INVALID;
			goto end;
		}
	}

	public_data = smw_keymgr_get_public_data(key_descriptor);
	public_length = smw_keymgr_get_public_length(key_descriptor);
	private_data = smw_keymgr_get_private_data(key_descriptor);
	private_length = smw_keymgr_get_private_length(key_descriptor);
	if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
		if (operation_id == OPERATION_ID_SIGN) {
			if (!private_data || !private_length) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}
		} else { // operation_id == OPERATION_ID_VERIFY
			if (!public_data || !public_length) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}
		}
	}

	status = smw_utils_execute_operation(operation_id, &sign_verify_args,
					     subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int sign_verify_init(enum operation_id operation_id,
			    struct smw_sign_verify_init_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_sign_verify_args sign_verify_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_descriptor = NULL;
	unsigned char *public_data = NULL;
	unsigned int public_length = 0;
	unsigned char *private_data = NULL;
	unsigned int private_length = 0;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context || !args->message != !args->message_length)
		goto end;

	if (args->context->op_state != CTX_OP_STATE_ALLOC) {
		status = SMW_STATUS_OPERATION_ALREADY_INIT;
		goto end;
	}

	status = sign_verify_init_convert_args(args, &sign_verify_args,
					       &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor = &sign_verify_args.key_descriptor;

	switch (operation_id) {
	case OPERATION_ID_SIGN_MULTI_PART:
		private_data = smw_keymgr_get_private_data(key_descriptor);
		private_length = smw_keymgr_get_private_length(key_descriptor);
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			if (!private_data || !private_length) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}
		}
		break;

	case OPERATION_ID_VERIFY_MULTI_PART:
		public_data = smw_keymgr_get_public_data(key_descriptor);
		public_length = smw_keymgr_get_public_length(key_descriptor);
		if (key_descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
			if (!public_data || !public_length) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}
		}
		break;

	default:
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_utils_execute_operation(operation_id, &sign_verify_args,
					     subsystem_id);

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

static int sign_verify_update(enum operation_id operation_id,
			      struct smw_sign_verify_update_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_crypto_sign_verify_args sign_verify_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->context || !args->message || !args->message_length)
		goto end;

	status = sign_verify_update_convert_args(args, &sign_verify_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_crypto_get_ctx_subsystem_id(args->context, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_update(operation_id, &sign_verify_args,
					  subsystem_id);

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

static int sign_verify_final(enum operation_id operation_id,
			     struct smw_sign_verify_final_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int tmp_status = SMW_STATUS_OK;
	struct smw_crypto_sign_verify_args sign_verify_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_API_CALL;

	/*
	 * Sign API can be called with a NULL signature pointer to get the
	 * signature length
	 */
	if (!args || !args->context)
		goto end;

	if (!args->message != !args->message_length)
		goto end;

	if (!args->signature != !args->signature_length)
		goto end;

	if (operation_id == OPERATION_ID_VERIFY_MULTI_PART && !args->signature)
		goto end;

	status = sign_verify_final_convert_args(args, &sign_verify_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_crypto_get_ctx_subsystem_id(args->context, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_final(operation_id, &sign_verify_args,
					 subsystem_id);

	/*
	 * Get output buffer length feature - If the output buffer is NULL and
	 * subsystem returns SMW_STATUS_OUTPUT_TOO_SHORT, update the status to
	 * SMW_STATUS_OK.
	 */
	if (operation_id == OPERATION_ID_SIGN_MULTI_PART) {
		if (status == SMW_STATUS_OUTPUT_TOO_SHORT && !args->signature) {
			status = SMW_STATUS_OK;
			goto end;
		}

		if (status == SMW_STATUS_OUTPUT_TOO_SHORT ||
		    status == SMW_STATUS_INVALID_PARAM)
			goto end;
	} else if (status == SMW_STATUS_INVALID_PARAM) {
		goto end;
	}

	tmp_status = smw_utils_free_context(&args->context);
	if (status == SMW_STATUS_OK)
		status = tmp_status;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned char *
smw_sign_verify_get_msg_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *message_buffer = NULL;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			message_buffer = args->oneshot_pub->message;
		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			message_buffer = args->init_pub->message;
		break;

	case SMW_OP_STEP_UPDATE:
		if (args->update_pub)
			message_buffer = args->update_pub->message;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			message_buffer = args->final_pub->message;
		break;

	default:
		break;
	}

	return message_buffer;
}

inline unsigned int
smw_sign_verify_get_msg_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int message_length = 0;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			message_length = args->oneshot_pub->message_length;
		break;

	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			message_length = args->init_pub->message_length;
		break;

	case SMW_OP_STEP_UPDATE:
		if (args->update_pub)
			message_length = args->update_pub->message_length;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			message_length = args->final_pub->message_length;
		break;

	default:
		break;
	}

	return message_length;
}

inline unsigned char *
smw_sign_verify_get_sign_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *signature_buffer = NULL;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			signature_buffer = args->oneshot_pub->signature;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			signature_buffer = args->final_pub->signature;
		break;

	default:
		break;
	}

	return signature_buffer;
}

inline unsigned int
smw_sign_verify_get_sign_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int signature_length = 0;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			signature_length = args->oneshot_pub->signature_length;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			signature_length = args->final_pub->signature_length;
		break;

	default:
		break;
	}

	return signature_length;
}

inline void
smw_sign_verify_copy_sign_buf(struct smw_crypto_sign_verify_args *args,
			      unsigned char *signature,
			      unsigned int signature_length)
{
	unsigned char *pub_sign = NULL;
	unsigned int pub_len = 0;

	if (signature && signature_length) {
		pub_sign = smw_sign_verify_get_sign_buf(args);
		pub_len = smw_sign_verify_get_sign_len(args);

		if (pub_sign && pub_len >= signature_length)
			SMW_UTILS_MEMCPY(pub_sign, signature, signature_length);
	}
}

inline void
smw_sign_verify_set_sign_len(struct smw_crypto_sign_verify_args *args,
			     unsigned int signature_length)
{
	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (args->oneshot_pub)
			args->oneshot_pub->signature_length = signature_length;
		break;

	case SMW_OP_STEP_FINAL:
		if (args->final_pub)
			args->final_pub->signature_length = signature_length;
		break;

	default:
		break;
	}
}

inline struct smw_eddsa_params *
smw_sign_verify_get_eddsa_context(struct smw_crypto_sign_verify_args *args)
{
	struct smw_eddsa_params *param = NULL;

	if (!args)
		return param;

	switch (args->op_step) {
	case SMW_OP_STEP_ONESHOT:
		if (!args->oneshot_pub || !args->oneshot_pub->eddsa_params)
			break;

		param = args->oneshot_pub->eddsa_params;
		break;

	case SMW_OP_STEP_INIT:
		if (!args->init_pub || !args->init_pub->eddsa_params)
			break;

		param = args->init_pub->eddsa_params;
		break;

	default:
		break;
	}

	if (param && (!param->context || !param->context_length))
		param = NULL;

	return param;
}

struct smw_op_context *
smw_sign_verify_get_op_context(struct smw_crypto_sign_verify_args *args)
{
	struct smw_op_context *ctx = NULL;

	if (!args)
		return ctx;

	switch (args->op_step) {
	case SMW_OP_STEP_INIT:
		if (args->init_pub)
			ctx = args->init_pub->context;

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

enum smw_status_code smw_sign(struct smw_sign_verify_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify(OPERATION_ID_SIGN, args);
}

enum smw_status_code smw_verify(struct smw_sign_verify_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify(OPERATION_ID_VERIFY, args);
}

enum smw_status_code smw_sign_init(struct smw_sign_verify_init_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify_init(OPERATION_ID_SIGN_MULTI_PART, args);
}

enum smw_status_code smw_sign_update(struct smw_sign_verify_update_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify_update(OPERATION_ID_SIGN_MULTI_PART, args);
}

enum smw_status_code smw_sign_final(struct smw_sign_verify_final_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify_final(OPERATION_ID_SIGN_MULTI_PART, args);
}

enum smw_status_code smw_verify_init(struct smw_sign_verify_init_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify_init(OPERATION_ID_VERIFY_MULTI_PART, args);
}

enum smw_status_code smw_verify_update(struct smw_sign_verify_update_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify_update(OPERATION_ID_VERIFY_MULTI_PART, args);
}

enum smw_status_code smw_verify_final(struct smw_sign_verify_final_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return sign_verify_final(OPERATION_ID_VERIFY_MULTI_PART, args);
}
