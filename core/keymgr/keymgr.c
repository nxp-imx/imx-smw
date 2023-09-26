// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include "smw_status.h"
#include "smw_keymgr.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "keymgr_db.h"
#include "exec.h"
#include "tlv.h"
#include "name.h"
#include "base64.h"
#include "attr.h"

#define FORMAT_ID_ASSERT(id)                                                   \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SMW_KEYMGR_FORMAT_ID_NB) &&              \
			       (_id != SMW_KEYMGR_FORMAT_ID_INVALID));         \
	} while (0)

#define SMW_KEYMGR_FORMAT_ID_DEFAULT SMW_KEYMGR_FORMAT_ID_HEX

static const char *const format_names[] = { [SMW_KEYMGR_FORMAT_ID_HEX] = "HEX",
					    [SMW_KEYMGR_FORMAT_ID_BASE64] =
						    "BASE64" };

static const char *const key_privacy_names[] = {
	[SMW_KEYMGR_PRIVACY_ID_PUBLIC] = "PUBLIC",
	[SMW_KEYMGR_PRIVACY_ID_PRIVATE] = "PRIVATE",
	[SMW_KEYMGR_PRIVACY_ID_PAIR] = "KEYPAIR",
};

#define KEY_PRIVACY_ID_ASSERT(id)                                              \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SMW_KEYMGR_PRIVACY_ID_NB) &&             \
			       (_id != SMW_KEYMGR_PRIVACY_ID_INVALID));        \
	} while (0)

static const char *const key_persistence_names[] = {
	[SMW_KEYMGR_PERSISTENCE_ID_TRANSIENT] = "TRANSIENT",
	[SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT] = "PERSISTENT",
	[SMW_KEYMGR_PERSISTENCE_ID_PERMANENT] = "PERMANENT",
};

#define KEY_PERSISTENCE_ID_ASSERT(id)                                          \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SMW_KEYMGR_PERSISTENCE_ID_NB) &&         \
			       (_id != SMW_KEYMGR_PERSISTENCE_ID_INVALID));    \
	} while (0)

/**
 * store_persistent() - Store persistent storage info.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Unused.
 * @length: Unused.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_persistent(void *attributes, unsigned char *value,
			    unsigned int length);

/**
 * store_rsa_pub_exp() - Store RSA public exponent key info.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to rsa public exponent buffer.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_rsa_pub_exp(void *attributes, unsigned char *value,
			     unsigned int length);

/**
 * store_flush_key() - Store flush key attribute.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Unused.
 * @length: Unused.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_flush_key(void *attributes, unsigned char *value,
			   unsigned int length);

/**
 * store_policy() - Store key policy.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to the key policy.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_policy(void *attributes, unsigned char *value,
			unsigned int length);

/**
 * store_storage_id() - Store key storage ID.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to the storage ID value.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_storage_id(void *attributes, unsigned char *value,
			    unsigned int length);

/*
 * Key policy is encoded as variable-length list TLV.
 * The syntax is verified by the Secure Subsystem when it is decoded.
 */
static const struct attribute_tlv keymgr_attributes_tlv_array[] = {
	{ .type = (const unsigned char *)PERSISTENT_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_persistent },
	{ .type = (const unsigned char *)RSA_PUB_EXP_STR,
	  .verify = smw_tlv_verify_large_numeral,
	  .store = store_rsa_pub_exp },
	{ .type = (const unsigned char *)FLUSH_KEY_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_flush_key },
	{ .type = (const unsigned char *)POLICY_STR,
	  .verify = smw_tlv_verify_variable_length_list,
	  .store = store_policy },
	{ .type = (const unsigned char *)STORAGE_ID_STR,
	  .verify = smw_tlv_verify_numeral,
	  .store = store_storage_id }
};

static int get_format_id(const char *name, enum smw_keymgr_format_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!name)
		*id = SMW_KEYMGR_FORMAT_ID_DEFAULT;
	else
		status =
			smw_utils_get_string_index(name, format_names,
						   SMW_KEYMGR_FORMAT_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static unsigned char **public_data_key_gen(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->public_data);
	return &this->keys->gen.public_data;
}

static unsigned int *public_length_key_gen(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->public_length);
	return &this->keys->gen.public_length;
}

static unsigned char **private_data_key_gen(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->private_data);
	return &this->keys->gen.private_data;
}

static unsigned int *private_length_key_gen(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->private_length);
	return &this->keys->gen.private_length;
}

static unsigned char **public_data_key_rsa(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->public_data);
	return &this->keys->rsa.public_data;
}

static unsigned int *public_length_key_rsa(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->public_length);
	return &this->keys->rsa.public_length;
}

static unsigned char **private_data_key_rsa(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->private_data);
	return &this->keys->rsa.private_data;
}

static unsigned int *private_length_key_rsa(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->private_length);
	return &this->keys->rsa.private_length;
}

static unsigned char **modulus_key_rsa(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->modulus);
	return &this->keys->rsa.modulus;
}

static unsigned int *modulus_length_key_rsa(struct smw_keymgr_key_ops *this)
{
	SMW_DBG_ASSERT(this && this->keys && this->modulus_length);
	return &this->keys->rsa.modulus_length;
}

/**
 * get_standard_private_length() - Get the private buffer standard length.
 * @identifier: Pointer to key identifier structure.
 * @format_id: Format ID.
 * @length: Pointer to the buffer length in bytes.
 *
 * This function computes the private key length depending of the
 * key type and format. The length is based on the cryptographic standard
 * and may be different on subsystem.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - Key type or format not valid
 */
static int get_standard_private_length(struct smw_keymgr_identifier *identifier,
				       enum smw_keymgr_format_id format_id,
				       unsigned int *length)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(identifier && length);

	*length = 0;

	switch (identifier->type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3:
	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		*length = BITS_TO_BYTES_SIZE(identifier->security_size);
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP:
		*length = 32;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DES:
		*length = 56;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DH:
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown type ID: %d\n",
			       identifier->type_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	switch (format_id) {
	case SMW_KEYMGR_FORMAT_ID_HEX:
		break;

	case SMW_KEYMGR_FORMAT_ID_BASE64:
		*length = smw_utils_get_base64_len(*length);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown format ID: %d\n", format_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_standard_public_length() - Get the public buffer standard length.
 * @identifier: Pointer to key identifier structure.
 * @format_id: Format ID.
 * @length: Pointer to the buffer length in bytes.
 *
 * This function computes the public key length depending of the
 * key type and format. The length is based on the cryptographic standard
 * and may be different on subsystem.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - Key type or format not valid
 */
static int get_standard_public_length(struct smw_keymgr_identifier *identifier,
				      enum smw_keymgr_format_id format_id,
				      unsigned int *length)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(identifier && length);

	*length = 0;

	switch (identifier->type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1:
		*length = BITS_TO_BYTES_SIZE(identifier->security_size) * 2;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DH:
		*length = BITS_TO_BYTES_SIZE(identifier->security_size);
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP:
		*length = 64;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3:
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		*length = DEFAULT_RSA_PUB_EXP_LEN;
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown type ID: %d\n",
			       identifier->type_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	switch (format_id) {
	case SMW_KEYMGR_FORMAT_ID_HEX:
		break;

	case SMW_KEYMGR_FORMAT_ID_BASE64:
		*length = smw_utils_get_base64_len(*length);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown format ID: %d\n", format_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * get_standard_modulus_length() - Get the modulus buffer standard length.
 * @identifier: Pointer to key identifier structure.
 * @format_id: Format ID.
 * @length: Pointer to the buffer length in bytes.
 *
 * This function computes the modulus key length depending of the
 * key type and format. The length is based on the cryptographic standard
 * and may be different on subsystem.
 *
 * Return:
 * SMW_STATUS_OK             - Success.
 * SMW_STATUS_INVALID_PARAM  - Key type or format not valid
 */
static int get_standard_modulus_length(struct smw_keymgr_identifier *identifier,
				       enum smw_keymgr_format_id format_id,
				       unsigned int *length)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(identifier && length);

	*length = 0;

	switch (identifier->type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_DH:
	case SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP:
	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3:
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		*length = BITS_TO_BYTES_SIZE(identifier->security_size);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown type ID: %d\n",
			       identifier->type_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	switch (format_id) {
	case SMW_KEYMGR_FORMAT_ID_HEX:
		break;

	case SMW_KEYMGR_FORMAT_ID_BASE64:
		*length = smw_utils_get_base64_len(*length);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown format ID: %d\n", format_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * setup_key_ops() - Setup the key operations in the key descriptor
 * @descriptor: key descriptor
 *
 * The operations depends on the key type.
 *
 * Return:
 * SMW_STATUS_OK             - Success
 * SMW_STATUS_INVALID_PARAM  - Wrong key descriptor
 * SMW_STATUS_NO_KEY_BUFFER  - Key buffer is not setup
 */
static int setup_key_ops(struct smw_keymgr_descriptor *descriptor)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_key_ops *ops = NULL;

	if (descriptor->pub) {
		ops = &descriptor->ops;
		/* Clear all operations */
		memset(ops, 0, sizeof(*ops));
		if (!descriptor->pub->buffer)
			return SMW_STATUS_NO_KEY_BUFFER;

		switch (descriptor->identifier.type_id) {
		case SMW_CONFIG_KEY_TYPE_ID_NB:
		case SMW_CONFIG_KEY_TYPE_ID_INVALID:
			break;

		case SMW_CONFIG_KEY_TYPE_ID_RSA:
			ops->keys = descriptor->pub->buffer;
			ops->public_data = &public_data_key_rsa;
			ops->public_length = &public_length_key_rsa;
			ops->private_data = &private_data_key_rsa;
			ops->private_length = &private_length_key_rsa;
			ops->modulus = &modulus_key_rsa;
			ops->modulus_length = &modulus_length_key_rsa;
			status = SMW_STATUS_OK;
			break;

		default:
			ops->keys = descriptor->pub->buffer;
			ops->public_data = &public_data_key_gen;
			ops->public_length = &public_length_key_gen;
			ops->private_data = &private_data_key_gen;
			ops->private_length = &private_length_key_gen;
			status = SMW_STATUS_OK;
			break;
		}
	}

	return status;
}

static int check_public_key_buffer(struct smw_keymgr_descriptor *key_desc,
				   bool mandatory)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *public_data = NULL;
	unsigned char *modulus = NULL;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);

	SMW_DBG_PRINTF(DEBUG, "public data=%p-%d\n", public_data,
		       public_length);

	if (!public_data && !mandatory) {
		status = SMW_STATUS_OK;
		goto end;
	} else if (public_data && !public_length) {
		goto end;
	}

	if (key_desc->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		modulus = smw_keymgr_get_modulus(key_desc);
		modulus_length = smw_keymgr_get_modulus_length(key_desc);

		SMW_DBG_PRINTF(DEBUG, "modulus data=%p-%d\n", modulus,
			       modulus_length);

		/*
		 * If the public data buffer is present, the modulus buffer
		 * must be set.
		 */
		if (!modulus || !modulus_length)
			goto end;
	}

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int check_private_key_buffer(struct smw_keymgr_descriptor *key_desc,
				    bool mandatory)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *private_data = NULL;
	unsigned int private_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	private_data = smw_keymgr_get_private_data(key_desc);
	private_length = smw_keymgr_get_private_length(key_desc);

	SMW_DBG_PRINTF(DEBUG, "private data=%p-%d\n", private_data,
		       private_length);

	if (!private_data && !mandatory)
		status = SMW_STATUS_OK;
	else if (private_data && private_length)
		status = SMW_STATUS_OK;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int check_generate_key_buffer(struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	unsigned char *private_data = NULL;
	unsigned int private_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_desc->pub || !key_desc->pub->buffer) {
		status = SMW_STATUS_OK;
		goto end;
	}

	/*
	 *  - private buffer must not be set
	 *  - public buffer must be set if user set the buffer argument.
	 */
	private_data = smw_keymgr_get_private_data(key_desc);
	private_length = smw_keymgr_get_private_length(key_desc);

	if (!private_data && !private_length)
		status = check_public_key_buffer(key_desc, true);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int check_import_key_buffer(struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * Either or both private and public buffer can be set
	 * (subsystem to check).
	 * If none is set, return in error.
	 */
	if (smw_keymgr_get_private_data(key_desc) ||
	    smw_keymgr_get_public_data(key_desc)) {
		status = check_private_key_buffer(key_desc, false);
		if (status == SMW_STATUS_OK)
			status = check_public_key_buffer(key_desc, false);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int check_export_key_buffer(struct smw_keymgr_descriptor *key_desc)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * Either or both private and public buffer can be set
	 * (subsystem to check).
	 * If none is set, return in error.
	 */
	if (smw_keymgr_get_private_data(key_desc) ||
	    smw_keymgr_get_public_data(key_desc)) {
		status = check_private_key_buffer(key_desc, false);
		if (status == SMW_STATUS_OK)
			status = check_public_key_buffer(key_desc, false);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_key_identifier(struct smw_keymgr_identifier *key_identifier,
			      enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_get_key_attributes_args attr_args = { 0 };

	attr_args.pub = NULL;
	attr_args.identifier.id = key_identifier->id;

	status = smw_utils_execute_implicit(OPERATION_ID_GET_KEY_ATTRIBUTES,
					    &attr_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	*key_identifier = attr_args.identifier;
	key_identifier->subsystem_id = subsystem_id;

	status = smw_keymgr_db_create(&key_identifier->id, key_identifier);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_keymgr_convert_descriptor(struct smw_key_descriptor *in,
				  struct smw_keymgr_descriptor *out,
				  bool new_key, enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_OK;

	enum smw_config_key_type_id type_id = SMW_CONFIG_KEY_TYPE_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(out);

	if (!in) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_config_get_key_type_id(in->type_name, &type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!in->buffer) {
		out->format_id = SMW_KEYMGR_FORMAT_ID_INVALID;
	} else {
		status =
			get_format_id(in->buffer->format_name, &out->format_id);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	out->identifier.id = in->id;
	out->identifier.type_id = type_id;
	out->identifier.security_size = in->security_size;

	if (in->id != INVALID_KEY_ID) {
		status = smw_keymgr_db_get_info(in->id, &out->identifier);

		if (status == SMW_STATUS_OK) {
			if (new_key ||
			    (in->type_name &&
			     type_id != out->identifier.type_id) ||
			    (in->security_size &&
			     in->security_size !=
				     out->identifier.security_size))
				status = SMW_STATUS_INVALID_PARAM;
		} else if (status == SMW_STATUS_UNKNOWN_ID) {
			if (new_key)
				status = SMW_STATUS_OK;
			else if (subsystem_id != SUBSYSTEM_ID_INVALID)
				status = get_key_identifier(&out->identifier,
							    subsystem_id);
		}

		if (status != SMW_STATUS_OK)
			goto end;
	}

	out->pub = in;
	(void)setup_key_ops(out);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_keymgr_convert_descriptors(struct smw_key_descriptor **in,
				   struct smw_keymgr_descriptor ***out,
				   unsigned int nb_keys,
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
	keymgr_desc = SMW_UTILS_CALLOC(nb_keys,
				       sizeof(struct smw_keymgr_descriptor *));
	if (!keymgr_desc)
		goto end;

	for (; i < nb_keys; i++) {
		key = in[i];

		/*
		 * This memory is freed at the end of one shot operation or
		 * cipher initialization
		 */
		keymgr_desc[i] =
			SMW_UTILS_CALLOC(1,
					 sizeof(struct smw_keymgr_descriptor));
		if (!keymgr_desc[i]) {
			status = SMW_STATUS_ALLOC_FAILURE;
			smw_keymgr_free_keys_ptr_array(keymgr_desc, nb_keys);
			goto end;
		}

		status = smw_keymgr_convert_descriptor(key, keymgr_desc[i],
						       false, *subsystem_id);
		if (status != SMW_STATUS_OK) {
			smw_keymgr_free_keys_ptr_array(keymgr_desc, nb_keys);
			goto end;
		}

		/*
		 * If @args->subsystem_name is not set and a key ID is set, get
		 * subsystem ID from key ID
		 */
		if (*subsystem_id == SUBSYSTEM_ID_INVALID && key->id)
			*subsystem_id = keymgr_desc[i]->identifier.subsystem_id;
	}

	*out = keymgr_desc;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_keymgr_set_default_attributes(struct smw_keymgr_attributes *attr)
{
	attr->persistence = SMW_KEYMGR_PERSISTENCE_ID_TRANSIENT;
	attr->rsa_pub_exp = NULL;
	attr->rsa_pub_exp_len = 0;
	attr->flush_key = false;
	attr->policy = NULL;
	attr->policy = 0;
	attr->pub_key_attributes_list = NULL;
	attr->pub_key_attributes_list_length = 0;
	attr->storage_id = 0;
}

int smw_keymgr_read_attributes(struct smw_keymgr_attributes *key_attrs,
			       unsigned char *attr_list,
			       unsigned int *attr_length)
{
	int status = read_attributes(attr_list, *attr_length, key_attrs,
				     keymgr_attributes_tlv_array,
				     ARRAY_SIZE(keymgr_attributes_tlv_array));

	key_attrs->pub_key_attributes_list = attr_list;
	key_attrs->pub_key_attributes_list_length = attr_length;

	return status;
}

void smw_keymgr_set_attributes_list(struct smw_keymgr_attributes *key_attrs,
				    unsigned char *attr_list,
				    unsigned int attr_length)
{
	SMW_DBG_ASSERT(key_attrs->pub_key_attributes_list);
	SMW_DBG_ASSERT(*key_attrs->pub_key_attributes_list_length >=
		       attr_length);

	SMW_DBG_PRINTF(DEBUG, "Attributes list set by caller:\n");
	SMW_DBG_HEX_DUMP(DEBUG, key_attrs->pub_key_attributes_list,
			 *key_attrs->pub_key_attributes_list_length, 4);

	SMW_DBG_PRINTF(DEBUG, "Attributes list returned:\n");
	SMW_DBG_HEX_DUMP(DEBUG, attr_list, attr_length, 4);

	SMW_UTILS_MEMCPY(key_attrs->pub_key_attributes_list, attr_list,
			 attr_length);
	*key_attrs->pub_key_attributes_list_length = attr_length;
}

static int
generate_key_convert_args(struct smw_generate_key_args *args,
			  struct smw_keymgr_generate_key_args *converted_args,
			  enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor,
					       true, SUBSYSTEM_ID_INVALID);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(&converted_args->key_attributes);

	status = smw_keymgr_read_attributes(&converted_args->key_attributes,
					    args->key_attributes_list,
					    &args->key_attributes_list_length);

	if (status == SMW_STATUS_OK) {
		/* RSA_PUB_EXP attribute must only be set for RSA key type */
		if (converted_args->key_descriptor.identifier.type_id !=
			    SMW_CONFIG_KEY_TYPE_ID_RSA &&
		    converted_args->key_attributes.rsa_pub_exp_len)
			status = SMW_STATUS_INVALID_PARAM;

		converted_args->key_descriptor.identifier.storage_id =
			converted_args->key_attributes.storage_id;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

//TODO: implement update_key_convert_args()
static int
update_key_convert_args(struct smw_update_key_args *args,
			struct smw_keymgr_update_key_args *converted_args,
			enum subsystem_id *subsystem_id)
{
	(void)converted_args;

	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
import_key_convert_args(struct smw_import_key_args *args,
			struct smw_keymgr_import_key_args *converted_args,
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
					       &converted_args->key_descriptor,
					       true, SUBSYSTEM_ID_INVALID);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(&converted_args->key_attributes);

	status = smw_keymgr_read_attributes(&converted_args->key_attributes,
					    args->key_attributes_list,
					    &args->key_attributes_list_length);

	if (status == SMW_STATUS_OK)
		converted_args->key_descriptor.identifier.storage_id =
			converted_args->key_attributes.storage_id;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
export_key_convert_args(struct smw_export_key_args *args,
			struct smw_keymgr_export_key_args *converted_args)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor,
					       false, SUBSYSTEM_ID_INVALID);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
delete_key_convert_args(struct smw_delete_key_args *args,
			struct smw_keymgr_delete_key_args *converted_args,
			enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version > 1) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(&converted_args->key_attributes);

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor,
					       false, SUBSYSTEM_ID_INVALID);
	if (status != SMW_STATUS_OK)
		goto end;

	*subsystem_id = converted_args->key_descriptor.identifier.subsystem_id;

	if (args->version < 1)
		goto end;

	status = smw_keymgr_read_attributes(&converted_args->key_attributes,
					    args->key_attributes_list,
					    &args->key_attributes_list_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_persistent(void *attributes, unsigned char *value,
			    unsigned int length)
{
	(void)value;
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->persistence = SMW_KEYMGR_PERSISTENCE_ID_PERSISTENT;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_rsa_pub_exp(void *attributes, unsigned char *value,
			     unsigned int length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->rsa_pub_exp = value;
		attr->rsa_pub_exp_len = length;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_flush_key(void *attributes, unsigned char *value,
			   unsigned int length)
{
	(void)value;
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->flush_key = true;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_policy(void *attributes, unsigned char *value,
			unsigned int length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->policy = value;
		attr->policy_len = length;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_storage_id(void *attributes, unsigned char *value,
			    unsigned int length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_keymgr_attributes *attr = attributes;
	unsigned long long numeral = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		numeral = smw_tlv_convert_numeral(length, value);
		if (numeral < UINT32_MAX) {
			attr->storage_id = numeral;

			status = SMW_STATUS_OK;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_keymgr_alloc_keypair_buffer(struct smw_keymgr_descriptor *descriptor,
				    unsigned int public_length,
				    unsigned int private_length)
{
	int status = SMW_STATUS_OK;

	struct smw_key_descriptor *pub = NULL;
	struct smw_keypair_buffer *buffer = NULL;
	unsigned char *public_data = NULL;
	unsigned char *private_data = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor || descriptor->pub) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	pub = SMW_UTILS_MALLOC(sizeof(struct smw_key_descriptor));
	if (!pub) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	buffer = SMW_UTILS_MALLOC(sizeof(struct smw_keypair_buffer));
	if (!buffer) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	pub->buffer = buffer;
	descriptor->pub = pub;

	status = setup_key_ops(descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	if (public_length) {
		public_data = SMW_UTILS_MALLOC(public_length);
		if (!public_data) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
	}

	if (private_length) {
		private_data = SMW_UTILS_MALLOC(private_length);
		if (!private_data) {
			status = SMW_STATUS_ALLOC_FAILURE;
			goto end;
		}
	}

	smw_keymgr_set_public_data(descriptor, public_data);
	smw_keymgr_set_public_length(descriptor, public_length);
	smw_keymgr_set_private_data(descriptor, private_data);
	smw_keymgr_set_private_length(descriptor, private_length);

end:
	if (status != SMW_STATUS_OK) {
		if (descriptor)
			descriptor->pub = NULL;

		if (public_data)
			SMW_UTILS_FREE(public_data);

		if (buffer)
			SMW_UTILS_FREE(buffer);

		if (pub)
			SMW_UTILS_FREE(pub);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_keymgr_free_keypair_buffer(struct smw_keymgr_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;
	unsigned char *data = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor || !descriptor->pub) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!descriptor->pub->buffer) {
		status = SMW_STATUS_NO_KEY_BUFFER;
		goto end;
	}

	/* Free public key data if defined */
	data = smw_keymgr_get_public_data(descriptor);
	if (data)
		SMW_UTILS_FREE(data);

	/* Free private key data if defined */
	data = smw_keymgr_get_private_data(descriptor);
	if (data)
		SMW_UTILS_FREE(data);

	SMW_UTILS_FREE(descriptor->pub->buffer);
	SMW_UTILS_FREE(descriptor->pub);
	descriptor->pub = NULL;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_keymgr_free_keys_ptr_array(struct smw_keymgr_descriptor **keys_desc,
				    unsigned int nb_keys)
{
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < nb_keys; i++) {
		if (keys_desc[i])
			SMW_UTILS_FREE(keys_desc[i]);
	}

	SMW_UTILS_FREE(keys_desc);
}

inline unsigned int
smw_keymgr_get_api_key_id(struct smw_keymgr_descriptor *descriptor)
{
	SMW_DBG_ASSERT(descriptor && descriptor->pub);

	return descriptor->pub->id;
}

inline unsigned char *
smw_keymgr_get_public_data(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;
	unsigned char *public_data = NULL;

	if (ops->public_data)
		public_data = *ops->public_data(ops);

	return public_data;
}

inline unsigned int
smw_keymgr_get_public_length(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;
	unsigned int public_length = 0;

	if (ops->public_length)
		public_length = *ops->public_length(ops);

	return public_length;
}

inline unsigned char *
smw_keymgr_get_private_data(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;
	unsigned char *private_data = NULL;

	if (ops->private_data)
		private_data = *ops->private_data(ops);

	return private_data;
}

inline unsigned int
smw_keymgr_get_private_length(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;
	unsigned int private_length = 0;

	if (ops->private_length)
		private_length = *ops->private_length(ops);

	return private_length;
}

inline unsigned char *
smw_keymgr_get_modulus(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;
	unsigned char *modulus = NULL;

	if (ops->modulus)
		modulus = *ops->modulus(ops);

	return modulus;
}

inline unsigned int
smw_keymgr_get_modulus_length(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;
	unsigned int modulus_length = 0;

	if (ops->modulus_length)
		modulus_length = *ops->modulus_length(ops);

	return modulus_length;
}

inline void smw_keymgr_set_public_data(struct smw_keymgr_descriptor *descriptor,
				       unsigned char *public_data)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;

	if (ops->public_data)
		*ops->public_data(ops) = public_data;
}

inline void
smw_keymgr_set_public_length(struct smw_keymgr_descriptor *descriptor,
			     unsigned int public_length)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;

	if (ops->public_length)
		*ops->public_length(ops) = public_length;
}

inline void
smw_keymgr_set_private_data(struct smw_keymgr_descriptor *descriptor,
			    unsigned char *private_data)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;

	if (ops->private_data)
		*ops->private_data(ops) = private_data;
}

inline void
smw_keymgr_set_private_length(struct smw_keymgr_descriptor *descriptor,
			      unsigned int private_length)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;

	if (ops->private_length)
		*ops->private_length(ops) = private_length;
}

inline void
smw_keymgr_set_modulus_length(struct smw_keymgr_descriptor *descriptor,
			      unsigned int modulus_length)
{
	struct smw_keymgr_key_ops *ops = &descriptor->ops;

	if (ops->modulus_length)
		*ops->modulus_length(ops) = modulus_length;
}

int smw_keymgr_update_public_buffer(struct smw_keymgr_descriptor *descriptor,
				    unsigned char *data, unsigned int length)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	unsigned char *pub_data = NULL;
	unsigned int pub_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	pub_data = smw_keymgr_get_public_data(descriptor);
	pub_length = smw_keymgr_get_public_length(descriptor);

	if (!length) {
		smw_keymgr_set_public_length(descriptor, length);
		SMW_DBG_PRINTF(DEBUG, "Public buffer length = %u\n", length);

		status = SMW_STATUS_OK;
	} else if (data && pub_data) {
		/* Update buffer data and length */
		if (descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			/* Encode hex_buffer in BASE64 buffer */
			status = smw_utils_base64_encode(data, length, pub_data,
							 &pub_length);
		} else {
			pub_length = length;
			status = SMW_STATUS_OK;
		}

		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			smw_keymgr_set_public_length(descriptor, pub_length);

		if (status == SMW_STATUS_OK) {
			SMW_DBG_PRINTF(DEBUG, "Public buffer:\n");
			SMW_DBG_HEX_DUMP(DEBUG, pub_data, pub_length, 4);
		}
	} else if (!data) {
		/* Update only the buffer length */
		pub_length = length;
		if (descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
			pub_length = smw_utils_get_base64_len(length);

		smw_keymgr_set_public_length(descriptor, pub_length);
		SMW_DBG_PRINTF(DEBUG, "Public buffer length = %u\n",
			       pub_length);

		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_keymgr_update_modulus_buffer(struct smw_keymgr_descriptor *descriptor,
				     unsigned char *data, unsigned int length)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	unsigned char *mod_data = NULL;
	unsigned int mod_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	mod_data = smw_keymgr_get_modulus(descriptor);
	mod_length = smw_keymgr_get_modulus_length(descriptor);

	if (!length) {
		smw_keymgr_set_modulus_length(descriptor, length);
		SMW_DBG_PRINTF(DEBUG, "Modulus buffer length = %u\n", length);

		status = SMW_STATUS_OK;
	} else if (data && mod_data) {
		/* Update buffer data and length */
		if (descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			/* Encode hex_buffer in BASE64 buffer */
			status = smw_utils_base64_encode(data, length, mod_data,
							 &mod_length);
		} else {
			mod_length = length;
			status = SMW_STATUS_OK;
		}

		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			smw_keymgr_set_modulus_length(descriptor, mod_length);

		if (status == SMW_STATUS_OK) {
			SMW_DBG_PRINTF(DEBUG, "Modulus buffer:\n");
			SMW_DBG_HEX_DUMP(DEBUG, mod_data, mod_length, 4);
		}
	} else if (!data) {
		/* Update only the buffer length */
		mod_length = length;
		if (descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
			mod_length = smw_utils_get_base64_len(length);

		smw_keymgr_set_modulus_length(descriptor, mod_length);
		SMW_DBG_PRINTF(DEBUG, "Modulus buffer length = %u\n",
			       mod_length);

		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_keymgr_update_private_buffer(struct smw_keymgr_descriptor *descriptor,
				     unsigned char *data, unsigned int length)
{
	int status = SMW_STATUS_OPERATION_FAILURE;
	unsigned char *priv_data = NULL;
	unsigned int priv_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	priv_data = smw_keymgr_get_private_data(descriptor);

	if (!length) {
		smw_keymgr_set_private_length(descriptor, length);
		SMW_DBG_PRINTF(DEBUG, "Private buffer length = %u\n", length);

		status = SMW_STATUS_OK;
	} else if (data && priv_data) {
		priv_length = smw_keymgr_get_private_length(descriptor);
		if (!priv_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		/* Update buffer data and length */
		if (descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64) {
			/* Encode hex_buffer in BASE64 buffer */
			status =
				smw_utils_base64_encode(data, length, priv_data,
							&priv_length);
		} else {
			priv_length = length;
			status = SMW_STATUS_OK;
		}

		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			smw_keymgr_set_private_length(descriptor, priv_length);

		if (status == SMW_STATUS_OK) {
			SMW_DBG_PRINTF(DEBUG, "Private buffer:\n");
			SMW_DBG_HEX_DUMP(DEBUG, priv_data, priv_length, 4);
		}
	} else if (!data) {
		/* Update only the buffer length */
		priv_length = length;
		if (descriptor->format_id == SMW_KEYMGR_FORMAT_ID_BASE64)
			priv_length = smw_utils_get_base64_len(length);

		smw_keymgr_set_private_length(descriptor, priv_length);
		SMW_DBG_PRINTF(DEBUG, "Private buffer length = %u\n",
			       priv_length);

		status = SMW_STATUS_OK;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_key_identifier(unsigned int id,
			      struct smw_keymgr_descriptor *descriptor)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor || !descriptor->pub)
		return status;

	if (descriptor->identifier.id != INVALID_KEY_ID) {
		status = smw_keymgr_db_update(id, &descriptor->identifier);

		if (status == SMW_STATUS_OK)
			descriptor->pub->id = id;
	} else {
		status = smw_keymgr_db_delete(id, &descriptor->identifier);
	}

	return status;
}

static void set_key_buffer_format(struct smw_keymgr_descriptor *descriptor)
{
	unsigned int index = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(descriptor);

	if (!descriptor->pub)
		return;

	if (!descriptor->pub->buffer)
		return;

	FORMAT_ID_ASSERT(descriptor->format_id);

	index = descriptor->format_id;
	descriptor->pub->buffer->format_name = format_names[index];
}

int smw_keymgr_get_privacy_id(enum smw_config_key_type_id type_id,
			      enum smw_keymgr_privacy_id *privacy_id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP:
	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		*privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3:
	case SMW_CONFIG_KEY_TYPE_ID_TLS_MASTER_KEY:
		*privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;
		break;

	default:
		*privacy_id = SMW_KEYMGR_PRIVACY_ID_INVALID;
		status = SMW_STATUS_INVALID_PARAM;
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_generate_key(struct smw_generate_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int ret = SMW_STATUS_OK;

	struct smw_keymgr_generate_key_args generate_key_args = { 0 };
	struct smw_keymgr_descriptor *key_desc = NULL;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	unsigned int new_id = INVALID_KEY_ID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor)
		goto end;

	if (!args->key_descriptor->type_name ||
	    !args->key_descriptor->security_size)
		goto end;

	status = generate_key_convert_args(args, &generate_key_args,
					   &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &generate_key_args.key_descriptor;

	status = check_generate_key_buffer(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc->identifier.persistence_id =
		generate_key_args.key_attributes.persistence;

	/*
	 * Try to create the key in the database before
	 * generating the key.
	 */
	status = smw_keymgr_db_create(&new_id, &key_desc->identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_GENERATE_KEY,
					     &generate_key_args, subsystem_id);
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		/* Delete the key from the database */
		(void)smw_keymgr_db_delete(new_id, &key_desc->identifier);
		goto end;
	}

	ret = set_key_identifier(new_id, key_desc);
	if (ret == SMW_STATUS_OK)
		set_key_buffer_format(key_desc);
	else
		status = ret;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_update_key(struct smw_update_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_update_key_args update_key_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = update_key_convert_args(args, &update_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_UPDATE_KEY,
					     &update_key_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_import_key(struct smw_import_key_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;
	int ret = SMW_STATUS_OK;

	struct smw_keymgr_import_key_args import_key_args = { 0 };
	struct smw_keymgr_descriptor *key_desc = NULL;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	unsigned int new_id = INVALID_KEY_ID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor ||
	    !args->key_descriptor->type_name ||
	    !args->key_descriptor->security_size)
		goto end;

	if (!args->key_descriptor->buffer) {
		status = SMW_STATUS_NO_KEY_BUFFER;
		goto end;
	}

	status = import_key_convert_args(args, &import_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &import_key_args.key_descriptor;

	status = check_import_key_buffer(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	/*
	 * Try to create the key in the database before
	 * importing the key.
	 */
	status = smw_keymgr_db_create(&new_id, &key_desc->identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_IMPORT_KEY,
					     &import_key_args, subsystem_id);
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_KEY_POLICY_WARNING_IGNORED) {
		/* Delete the key from the database */
		(void)smw_keymgr_db_delete(new_id, &key_desc->identifier);
		goto end;
	}

	if (smw_keymgr_get_public_data(key_desc) &&
	    smw_keymgr_get_private_data(key_desc))
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
	else if (smw_keymgr_get_public_data(key_desc))
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
	else if (smw_keymgr_get_private_data(key_desc))
		/* Only private data is set */
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;
	else
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_INVALID;

	key_desc->identifier.persistence_id =
		import_key_args.key_attributes.persistence;

	ret = set_key_identifier(new_id, key_desc);
	if (ret == SMW_STATUS_OK)
		set_key_buffer_format(key_desc);
	else
		status = ret;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_export_key(struct smw_export_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args export_key_args = { 0 };
	struct smw_keymgr_descriptor *key_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor || !args->key_descriptor->id) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->key_descriptor->buffer) {
		status = SMW_STATUS_NO_KEY_BUFFER;
		goto end;
	}

	status = export_key_convert_args(args, &export_key_args);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &export_key_args.key_descriptor;

	status = check_export_key_buffer(key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_EXPORT_KEY,
					     &export_key_args,
					     key_desc->identifier.subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	set_key_buffer_format(key_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_delete_key(struct smw_delete_key_args *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	struct smw_keymgr_delete_key_args delete_key_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = delete_key_convert_args(args, &delete_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &delete_key_args.key_descriptor;

	status = smw_utils_execute_operation(OPERATION_ID_DELETE_KEY,
					     &delete_key_args, subsystem_id);

	if (status != SMW_STATUS_OK && status != SMW_STATUS_UNKNOWN_ID)
		goto end;

	tmp_status = smw_keymgr_db_delete(args->key_descriptor->id,
					  &key_desc->identifier);

	if (status == SMW_STATUS_OK ||
	    key_desc->identifier.persistence_id !=
		    SMW_KEYMGR_PERSISTENCE_ID_TRANSIENT)
		status = tmp_status;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_descriptor key_desc = { 0 };
	unsigned int public_length = 0;
	unsigned int private_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor)
		goto end;

	if (!descriptor->type_name || !descriptor->security_size)
		goto end;

	if (!descriptor->buffer) {
		status = SMW_STATUS_NO_KEY_BUFFER;
		goto end;
	}

	status = smw_keymgr_convert_descriptor(descriptor, &key_desc, false,
					       SUBSYSTEM_ID_INVALID);
	if (status != SMW_STATUS_OK)
		goto end;

	if (key_desc.identifier.id == INVALID_KEY_ID) {
		status = get_standard_public_length(&key_desc.identifier,
						    key_desc.format_id,
						    &public_length);
		if (status != SMW_STATUS_OK)
			goto end;

		status = get_standard_modulus_length(&key_desc.identifier,
						     key_desc.format_id,
						     &modulus_length);
		if (status != SMW_STATUS_OK)
			goto end;

		status = get_standard_private_length(&key_desc.identifier,
						     key_desc.format_id,
						     &private_length);
		if (status != SMW_STATUS_OK)
			goto end;

		smw_keymgr_set_public_length(&key_desc, public_length);
		smw_keymgr_set_private_length(&key_desc, private_length);
		smw_keymgr_set_modulus_length(&key_desc, modulus_length);

		goto end;
	}

	status = smw_utils_execute_implicit(OPERATION_ID_GET_KEY_LENGTHS,
					    &key_desc,
					    key_desc.identifier.subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_get_key_type_name(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier key_identifier = { 0 };
	const char *name = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_keymgr_db_get_info(descriptor->id, &key_identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_config_get_key_type_name(key_identifier.type_id, &name);

	descriptor->type_name = name;

	if (!name)
		status = SMW_STATUS_INVALID_PARAM;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_get_security_size(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier key_identifier = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_keymgr_db_get_info(descriptor->id, &key_identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	descriptor->security_size = key_identifier.security_size;

	if (!key_identifier.security_size)
		status = SMW_STATUS_INVALID_PARAM;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_keymgr_set_policy(struct smw_keymgr_get_key_attributes_args *attrs,
			   unsigned char *policy, unsigned int length)
{
	if (attrs && attrs->pub) {
		attrs->pub->policy_list = policy;
		attrs->pub->policy_list_length = length;
	}
}

void smw_keymgr_set_lifecycle(struct smw_keymgr_get_key_attributes_args *attrs,
			      unsigned char *lifecycle, unsigned int length)
{
	if (attrs && attrs->pub) {
		attrs->pub->lifecycle_list = lifecycle;
		attrs->pub->lifecycle_list_length = length;
	}
}

enum smw_status_code
smw_get_key_attributes(struct smw_get_key_attributes_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_get_key_attributes_args attr_args = { 0 };
	struct smw_keymgr_identifier *key_identifier = &attr_args.identifier;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	bool key_not_present = false;
	unsigned int index = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_db_get_info(args->key_descriptor->id,
					key_identifier);

	if (status == SMW_STATUS_OK) {
		if (subsystem_id == SUBSYSTEM_ID_INVALID) {
			subsystem_id = key_identifier->subsystem_id;
		} else if (subsystem_id != key_identifier->subsystem_id) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	} else if (status == SMW_STATUS_UNKNOWN_ID) {
		if (subsystem_id == SUBSYSTEM_ID_INVALID) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		key_identifier->id = args->key_descriptor->id;
		key_not_present = true;
	} else {
		goto end;
	}

	attr_args.pub = args;
	smw_keymgr_set_policy(&attr_args, NULL, 0);
	smw_keymgr_set_lifecycle(&attr_args, NULL, 0);

	status = smw_utils_execute_implicit(OPERATION_ID_GET_KEY_ATTRIBUTES,
					    &attr_args, subsystem_id);

	if (status != SMW_STATUS_OK)
		goto end;

	/* Convert the key type */
	smw_config_get_key_type_name(key_identifier->type_id,
				     &args->key_descriptor->type_name);

	/* Set the key security size */
	args->key_descriptor->security_size = key_identifier->security_size;

	KEY_PRIVACY_ID_ASSERT(key_identifier->privacy_id);
	index = key_identifier->privacy_id;
	args->key_privacy = key_privacy_names[index];

	KEY_PERSISTENCE_ID_ASSERT(key_identifier->persistence_id);
	index = key_identifier->persistence_id;
	args->persistence = key_persistence_names[index];

	args->storage = key_identifier->storage_id;

	if (key_not_present) {
		key_identifier->subsystem_id = subsystem_id;
		status = smw_keymgr_db_create(&key_identifier->id,
					      key_identifier);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_commit_key_storage(struct smw_commit_key_storage_args *args)
{
	int status = SMW_STATUS_INVALID_PARAM;

	struct smw_keymgr_commit_key_storage_args commit_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args)
		goto end;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	commit_args.pub = args;

	status = smw_utils_execute_implicit(OPERATION_ID_COMMIT_KEY_STORAGE,
					    &commit_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
