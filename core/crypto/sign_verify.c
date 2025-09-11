// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2025 NXP
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
			 struct smw_crypto_sign_verify_args *converted_args,
			 enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	bool new_key = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor,
					       &new_key, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = sign_verify_convert_attributes(args->sign_algo,
						&converted_args->attributes);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->pub = args;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned char *
smw_sign_verify_get_msg_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *message_buffer = NULL;

	if (args->pub)
		message_buffer = args->pub->message;

	return message_buffer;
}

inline unsigned int
smw_sign_verify_get_msg_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int message_length = 0;

	if (args->pub)
		message_length = args->pub->message_length;

	return message_length;
}

inline unsigned char *
smw_sign_verify_get_sign_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *signature_buffer = NULL;

	if (args->pub)
		signature_buffer = args->pub->signature;

	return signature_buffer;
}

inline unsigned int
smw_sign_verify_get_sign_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int signature_length = 0;

	if (args->pub)
		signature_length = args->pub->signature_length;

	return signature_length;
}

inline void
smw_sign_verify_copy_sign_buf(struct smw_crypto_sign_verify_args *args,
			      unsigned char *signature,
			      unsigned int signature_length)
{
	if (args->pub && args->pub->signature_length >= signature_length) {
		SMW_UTILS_MEMCPY(args->pub->signature, signature,
				 signature_length);
	}
}

inline void
smw_sign_verify_set_sign_len(struct smw_crypto_sign_verify_args *args,
			     unsigned int signature_length)
{
	if (args->pub)
		args->pub->signature_length = signature_length;
}

inline unsigned char *
smw_sign_verify_get_eddsactx_buf(struct smw_crypto_sign_verify_args *args)
{
	unsigned char *context_buffer = NULL;

	if (args->pub && args->pub->eddsa_params)
		context_buffer = args->pub->eddsa_params->context;

	return context_buffer;
}

inline unsigned int
smw_sign_verify_get_eddsactx_len(struct smw_crypto_sign_verify_args *args)
{
	unsigned int context_length = 0;

	if (args->pub && args->pub->eddsa_params)
		context_length = args->pub->eddsa_params->context_length;

	return context_length;
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

static int smw_sign_verify(enum operation_id operation_id,
			   struct smw_sign_verify_args *args)
{
	int status = SMW_STATUS_OK;

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
	if (!args ||
	    (!args->signature && operation_id == OPERATION_ID_VERIFY) ||
	    (args->signature && (!args->message || !args->message_length ||
				 !args->signature_length))) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

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

enum smw_status_code smw_sign(struct smw_sign_verify_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return smw_sign_verify(OPERATION_ID_SIGN, args);
}

enum smw_status_code smw_verify(struct smw_sign_verify_args *args)
{
	SMW_DBG_TRACE_API_CALL;

	return smw_sign_verify(OPERATION_ID_VERIFY, args);
}
