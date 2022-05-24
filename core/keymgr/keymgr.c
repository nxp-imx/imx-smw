// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
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

#define SMW_KEYMGR_FORMAT_ID_DEFAULT SMW_KEYMGR_FORMAT_ID_HEX

static const char *const format_names[] = { [SMW_KEYMGR_FORMAT_ID_HEX] = "HEX",
					    [SMW_KEYMGR_FORMAT_ID_BASE64] =
						    "BASE64" };

/**
 * store_persistent() - Store persistent storage info.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Unused.
 * @length: Unused.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- key_attributes is NULL.
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
 * SMW_STATUS_INVALID_PARAM	- @key_attributes is NULL.
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
 * SMW_STATUS_INVALID_PARAM	- key_attributes is NULL.
 */
static int store_flush_key(void *attributes, unsigned char *value,
			   unsigned int length);

static const struct attribute_tlv keymgr_attributes_tlv_array[] = {
	{ .type = (const unsigned char *)PERSISTENT_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_persistent },
	{ .type = (const unsigned char *)RSA_PUB_EXP_STR,
	  .verify = smw_tlv_verify_large_numeral,
	  .store = store_rsa_pub_exp },
	{ .type = (const unsigned char *)FLUSH_KEY_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_flush_key }
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
	struct smw_keymgr_key_ops *ops;

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

int smw_keymgr_convert_descriptor(struct smw_key_descriptor *in,
				  struct smw_keymgr_descriptor *out)
{
	int status = SMW_STATUS_OK;

	enum smw_config_key_type_id type_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(out);

	if (!in) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_config_get_key_type_id(in->type_name, &type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	if (in->id != INVALID_KEY_ID) {
		status = smw_keymgr_db_get_info(in->id, &out->identifier);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (!in->buffer) {
		out->format_id = SMW_KEYMGR_FORMAT_ID_INVALID;
	} else {
		status =
			get_format_id(in->buffer->format_name, &out->format_id);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	if (in->id != INVALID_KEY_ID && in->type_name) {
		if (type_id != out->identifier.type_id) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	if (in->id != INVALID_KEY_ID && in->security_size) {
		if (in->security_size != out->identifier.security_size) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	if (in->id == INVALID_KEY_ID) {
		out->identifier.type_id = type_id;
		out->identifier.security_size = in->security_size;
	}

	out->pub = in;
	status = setup_key_ops(out);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_keymgr_set_default_attributes(struct smw_keymgr_attributes *attr)
{
	attr->persistent_storage = false;
	attr->rsa_pub_exp = NULL;
	attr->rsa_pub_exp_len = 0;
	attr->flush_key = false;
}

int smw_keymgr_read_attributes(struct smw_keymgr_attributes *key_attrs,
			       const unsigned char *attr_list,
			       unsigned int attr_length)
{
	int status;

	status = read_attributes(attr_list, attr_length, key_attrs,
				 keymgr_attributes_tlv_array,
				 ARRAY_SIZE(keymgr_attributes_tlv_array));

	return status;
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

	args->key_descriptor->id = INVALID_KEY_ID;
	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
		goto end;

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(&converted_args->key_attributes);

	status = smw_keymgr_read_attributes(&converted_args->key_attributes,
					    args->key_attributes_list,
					    args->key_attributes_list_length);

	if (status == SMW_STATUS_OK) {
		/* RSA_PUB_EXP attribute must only be set for RSA key type */
		if (converted_args->key_descriptor.identifier.type_id !=
			    SMW_CONFIG_KEY_TYPE_ID_RSA &&
		    converted_args->key_attributes.rsa_pub_exp_len)
			status = SMW_STATUS_INVALID_PARAM;
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

	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

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

	args->key_descriptor->id = INVALID_KEY_ID;
	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(&converted_args->key_attributes);

	status = smw_keymgr_read_attributes(&converted_args->key_attributes,
					    args->key_attributes_list,
					    args->key_attributes_list_length);

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
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

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

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_NO_KEY_BUFFER)
		goto end;

	*subsystem_id = converted_args->key_descriptor.identifier.subsystem_id;

	status = SMW_STATUS_OK;
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
		attr->persistent_storage = true;
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
	unsigned char *data;

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

static int set_key_identifier(unsigned int id,
			      struct smw_keymgr_descriptor *descriptor)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor || !descriptor->pub)
		return SMW_STATUS_INVALID_PARAM;

	status = smw_keymgr_db_update(id, &descriptor->identifier);

	if (status == SMW_STATUS_OK)
		descriptor->pub->id = id;

	return status;
}

static void set_key_buffer_format(struct smw_keymgr_descriptor *descriptor)
{
	unsigned int format_index;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(descriptor);

	if (!descriptor->pub)
		return;

	if (!descriptor->pub->buffer)
		return;

	SMW_DBG_ASSERT(descriptor->format_id < SMW_KEYMGR_FORMAT_ID_NB &&
		       descriptor->format_id != SMW_KEYMGR_FORMAT_ID_INVALID);
	format_index = descriptor->format_id;
	descriptor->pub->buffer->format_name = format_names[format_index];
}

int smw_keymgr_get_buffers_lengths(struct smw_keymgr_identifier *identifier,
				   enum smw_keymgr_format_id format_id,
				   unsigned int *public_buffer_length,
				   unsigned int *private_buffer_length,
				   unsigned int *modulus_buffer_length)
{
	int status = SMW_STATUS_OK;
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_ASSERT(identifier);

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (identifier->type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDH_BRAINPOOL_T1:
		public_length =
			BITS_TO_BYTES_SIZE(identifier->security_size) * 2;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DH:
		public_length = BITS_TO_BYTES_SIZE(identifier->security_size);
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP:
		public_length = 64;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_MD5:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA1:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA224:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA256:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA384:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SHA512:
	case SMW_CONFIG_KEY_TYPE_ID_HMAC_SM3:
		public_length = 0;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_RSA:
		modulus_length = BITS_TO_BYTES_SIZE(identifier->security_size);

		/*
		 * If attribute field is set, it represents the public
		 * exponent length in bytes.
		 * Else, public length is set to the default value.
		 */
		if (identifier->attribute)
			public_length = identifier->attribute;
		else
			public_length = DEFAULT_RSA_PUB_EXP_LEN;
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
		public_length = smw_utils_get_base64_len(public_length);
		modulus_length = smw_utils_get_base64_len(modulus_length);
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown format ID: %d\n", format_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (public_buffer_length)
		*public_buffer_length = public_length;

	if (private_buffer_length)
		//TODO: export of pivate key is not supported now
		*private_buffer_length = 0;

	if (modulus_buffer_length)
		*modulus_buffer_length = modulus_length;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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

	struct smw_keymgr_generate_key_args generate_key_args = { 0 };
	struct smw_keymgr_descriptor *key_desc;
	struct smw_keymgr_attributes *key_attr;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	unsigned char *public_data;
	unsigned char *private_data;
	unsigned char *modulus;
	unsigned int private_length;
	unsigned int public_length;
	unsigned int modulus_length;
	unsigned int exp_pub_length;
	unsigned int exp_modulus_length;
	unsigned int new_id = INVALID_KEY_ID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor)
		goto end;

	if (!args->key_descriptor->type_name ||
	    !args->key_descriptor->security_size || args->key_descriptor->id)
		goto end;

	status = generate_key_convert_args(args, &generate_key_args,
					   &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &generate_key_args.key_descriptor;
	key_attr = &generate_key_args.key_attributes;

	if (args->key_descriptor->buffer) {
		status = smw_keymgr_get_buffers_lengths(&key_desc->identifier,
							key_desc->format_id,
							&exp_pub_length, NULL,
							&exp_modulus_length);
		if (status != SMW_STATUS_OK)
			goto end;

		/* Case where RSA public exponent is set by the user */
		if (key_desc->identifier.type_id ==
			    SMW_CONFIG_KEY_TYPE_ID_RSA &&
		    key_attr->rsa_pub_exp_len)
			exp_pub_length = key_attr->rsa_pub_exp_len;

		public_data = smw_keymgr_get_public_data(key_desc);
		public_length = smw_keymgr_get_public_length(key_desc);
		private_data = smw_keymgr_get_private_data(key_desc);
		private_length = smw_keymgr_get_private_length(key_desc);
		modulus = smw_keymgr_get_modulus(key_desc);
		modulus_length = smw_keymgr_get_modulus_length(key_desc);

		if ((public_data && public_length < exp_pub_length) ||
		    (modulus && modulus_length < exp_modulus_length) ||
		    private_data || private_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		if (key_desc->identifier.type_id ==
		    SMW_CONFIG_KEY_TYPE_ID_RSA) {
			/*
			 * For RSA keys, public data and modulus must be set to
			 * export the public key
			 */
			if ((modulus && !public_data) ||
			    (!modulus && public_data)) {
				status = SMW_STATUS_INVALID_PARAM;
				goto end;
			}
		}
	}

	/*
	 * Try to create the key in the database before
	 * generating the key.
	 */
	status = smw_keymgr_db_create(&new_id, &key_desc->identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_GENERATE_KEY,
					     &generate_key_args, subsystem_id);
	if (status != SMW_STATUS_OK) {
		/* Delete the key from the database */
		(void)smw_keymgr_db_delete(new_id, &key_desc->identifier);
		goto end;
	}

	if (generate_key_args.key_attributes.persistent_storage)
		key_desc->identifier.persistent = true;
	else
		key_desc->identifier.persistent = false;

	status = set_key_identifier(new_id, key_desc);
	if (status == SMW_STATUS_OK)
		set_key_buffer_format(key_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_update_key(struct smw_update_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_update_key_args update_key_args;
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
	int status = SMW_STATUS_OK;

	struct smw_keymgr_import_key_args import_key_args = { 0 };
	struct smw_keymgr_descriptor *key_desc;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	unsigned char *public_data;
	unsigned char *private_data;
	unsigned char *modulus;
	unsigned int private_length;
	unsigned int public_length;
	unsigned int modulus_length;
	unsigned int new_id = INVALID_KEY_ID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor ||
	    !args->key_descriptor->type_name ||
	    !args->key_descriptor->security_size || args->key_descriptor->id) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->key_descriptor->buffer) {
		status = SMW_STATUS_NO_KEY_BUFFER;
		goto end;
	}

	status = import_key_convert_args(args, &import_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &import_key_args.key_descriptor;

	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);
	private_data = smw_keymgr_get_private_data(key_desc);
	private_length = smw_keymgr_get_private_length(key_desc);

	if ((!public_data && !private_data) ||
	    (public_data && !public_length) ||
	    (!public_data && public_length) ||
	    (private_data && !private_length) ||
	    (!private_data && private_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (import_key_args.key_descriptor.identifier.type_id ==
	    SMW_CONFIG_KEY_TYPE_ID_RSA) {
		modulus = smw_keymgr_get_modulus(key_desc);
		modulus_length = smw_keymgr_get_modulus_length(key_desc);

		/*
		 * Regardless to the key type to import (public key, private key
		 * or keypair) modulus must be set
		 */
		if (!modulus || !modulus_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	/*
	 * Try to create the key in the database before
	 * importing the key.
	 */
	status = smw_keymgr_db_create(&new_id, &key_desc->identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_IMPORT_KEY,
					     &import_key_args, subsystem_id);
	if (status != SMW_STATUS_OK) {
		/* Delete the key from the database */
		(void)smw_keymgr_db_delete(new_id, &key_desc->identifier);
		goto end;
	}

	if (public_data && private_data)
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
	else if (public_data)
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
	else
		/* Only private data is set */
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	if (import_key_args.key_attributes.persistent_storage)
		key_desc->identifier.persistent = true;
	else
		key_desc->identifier.persistent = false;

	status = set_key_identifier(new_id, key_desc);
	if (status == SMW_STATUS_OK)
		set_key_buffer_format(key_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_export_key(struct smw_export_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args export_key_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_desc;
	unsigned char *public_data;
	unsigned char *private_data;
	unsigned char *modulus = NULL;
	unsigned int private_length;
	unsigned int public_length;
	unsigned int modulus_length = 0;
	unsigned int exp_pub_length;
	unsigned int exp_priv_length;
	unsigned int exp_modulus_length;

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

	public_data = smw_keymgr_get_public_data(key_desc);
	public_length = smw_keymgr_get_public_length(key_desc);
	private_data = smw_keymgr_get_private_data(key_desc);
	private_length = smw_keymgr_get_private_length(key_desc);

	if ((!public_data && !private_data) ||
	    (public_data && !public_length) ||
	    (!public_data && public_length) ||
	    (private_data && !private_length) ||
	    (!private_data && private_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (key_desc->identifier.type_id == SMW_CONFIG_KEY_TYPE_ID_RSA) {
		modulus = smw_keymgr_get_modulus(key_desc);
		modulus_length = smw_keymgr_get_modulus_length(key_desc);

		/*
		 * Regardless to the key type to import (public key, private key
		 * or keypair) modulus must be set
		 */
		if (!modulus || !modulus_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	subsystem_id = key_desc->identifier.subsystem_id;

	status = smw_keymgr_get_buffers_lengths(&key_desc->identifier,
						key_desc->format_id,
						&exp_pub_length,
						&exp_priv_length,
						&exp_modulus_length);
	if (status != SMW_STATUS_OK)
		goto end;

	if ((public_data && public_length < exp_pub_length) ||
	    (private_data && private_length < exp_priv_length) ||
	    (modulus && modulus_length < exp_modulus_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_EXPORT_KEY,
					     &export_key_args, subsystem_id);
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

	struct smw_keymgr_delete_key_args delete_key_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_desc;

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

	if (status == SMW_STATUS_OK)
		status = smw_keymgr_db_delete(args->key_descriptor->id,
					      &key_desc->identifier);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor key_desc = { 0 };
	unsigned int public_length;
	unsigned int private_length;
	unsigned int modulus_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!descriptor->type_name || !descriptor->security_size) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!descriptor->buffer) {
		status = SMW_STATUS_NO_KEY_BUFFER;
		goto end;
	}

	status = smw_keymgr_convert_descriptor(descriptor, &key_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_get_buffers_lengths(&key_desc.identifier,
						key_desc.format_id,
						&public_length, &private_length,
						&modulus_length);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_keymgr_set_public_length(&key_desc, public_length);
	smw_keymgr_set_private_length(&key_desc, private_length);
	smw_keymgr_set_modulus_length(&key_desc, modulus_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code
smw_get_key_type_name(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier key_identifier = { 0 };
	const char *name;

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
