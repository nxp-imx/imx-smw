// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

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
#include "tlv.h"
#include "attr.h"

/**
 * store_signature_type() - Store signature type.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Signature type string.
 * @length: Length of @value in bytes.
 *
 * @value is converted in 'enum smw_config_sign_type_id'.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_signature_type(void *attributes, unsigned char *value,
				unsigned int length);

/**
 * store_salt_len() - Store optional salt length.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Salt length (HEX buffer).
 * @length: @value length in bytes.
 *
 * @value is converted in uint32_t.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameters is invalid.
 */
static int store_salt_len(void *attributes, unsigned char *value,
			  unsigned int length);

/**
 * store_tls_mac_finish_label() - Store TLS finished message label.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Label string.
 * @length: Length of @value in bytes.
 *
 * The parameter @value is converted in
 * 'enum smw_config_tls_mac_finish_label_id'.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_tls_mac_finish_label(void *attributes, unsigned char *value,
				      unsigned int length);

static struct attribute_tlv sign_verify_attributes_tlv_array[] = {
	{ .type = (const unsigned char *)SIGNATURE_TYPE_STR,
	  .verify = smw_tlv_verify_enumeration,
	  .store = store_signature_type },
	{ .type = (const unsigned char *)SALT_LEN_STR,
	  .verify = smw_tlv_verify_numeral,
	  .store = store_salt_len },
	{ .type = (const unsigned char *)TLS_MAC_FINISH_STR,
	  .verify = smw_tlv_verify_enumeration,
	  .store = store_tls_mac_finish_label }
};

/**
 * set_default_attributes() - Set default sign/verify attributes
 * @attr: Pointer to the sign/verify attributes structure.
 *
 * Return:
 * None.
 */
static void set_default_attributes(struct smw_sign_verify_attributes *attr)
{
	attr->signature_type = SMW_CONFIG_SIGN_TYPE_ID_DEFAULT;
	attr->salt_length = 0;
	attr->tls_label = SMW_CONFIG_TLS_FINISH_ID_INVALID;
}

static int
sign_verify_convert_args(struct smw_sign_verify_args *args,
			 struct smw_crypto_sign_verify_args *converted_args,
			 enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

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
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
		goto end;

	status = smw_config_get_hash_algo_id(args->algo_name,
					     &converted_args->algo_id);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Initialize attributes parameters to default values */
	set_default_attributes(&converted_args->attributes);

	status = read_attributes(args->attributes_list,
				 args->attributes_list_length,
				 &converted_args->attributes,
				 sign_verify_attributes_tlv_array,
				 ARRAY_SIZE(sign_verify_attributes_tlv_array));
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

static int store_signature_type(void *attributes, unsigned char *value,
				unsigned int length)
{
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_sign_verify_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!value || !attr)
		goto end;

	status = smw_config_get_signature_type_id((char *)value,
						  &attr->signature_type);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_salt_len(void *attributes, unsigned char *value,
			  unsigned int length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_sign_verify_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!value || !attr)
		goto end;

	attr->salt_length = (uint32_t)smw_tlv_convert_numeral(length, value);
	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_tls_mac_finish_label(void *attributes, unsigned char *value,
				      unsigned int length)
{
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_sign_verify_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!value || !attr)
		goto end;

	status = smw_config_get_tls_label_id((char *)value, &attr->tls_label);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static unsigned int get_sign_size(struct smw_keymgr_descriptor *key)
{
	switch (key->identifier.type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
		/* Signature size is public key size */
		return BITS_TO_BYTES_SIZE(key->identifier.security_size) * 2;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		/* Signature size is modulus size */
		return BITS_TO_BYTES_SIZE(key->identifier.security_size);

	case SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY:
		return TLS12_MAC_FINISH_DEFAULT_LEN;

	default:
		return 0;
	}
}

static int smw_sign_verify(enum operation_id operation_id,
			   struct smw_sign_verify_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_crypto_sign_verify_args sign_verify_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_descriptor;
	enum smw_keymgr_format_id format_id;
	unsigned char *public_data;
	unsigned int public_length;
	unsigned char *private_data;
	unsigned int private_length;

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

	format_id = key_descriptor->format_id;
	public_data = smw_keymgr_get_public_data(key_descriptor);
	public_length = smw_keymgr_get_public_length(key_descriptor);
	private_data = smw_keymgr_get_private_data(key_descriptor);
	private_length = smw_keymgr_get_private_length(key_descriptor);
	if (format_id != SMW_KEYMGR_FORMAT_ID_INVALID) {
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
	return smw_sign_verify(OPERATION_ID_SIGN, args);
}

enum smw_status_code smw_verify(struct smw_sign_verify_args *args)
{
	return smw_sign_verify(OPERATION_ID_VERIFY, args);
}
