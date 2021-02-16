// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"
#include "smw_keymgr.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "keymgr.h"
#include "exec.h"
#include "tlv.h"
#include "name.h"
#include "base64.h"

/*
 * Key identifier is encoded as described below.
 * P is Privacy ID.
 *
 *   0   1   2   3   4   5   6   7   8   9  11  12  13  14  15
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * | Subsystem ID  |            Key type ID            |   P   |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                       Securty size                        |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                            ID                             |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 * |                            ID                             |
 * +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */

#define ID_LENGTH	     32
#define SECURITY_SIZE_LENGTH 16
#define PRIVACY_ID_LENGTH    2
#define TYPE_ID_LENGTH	     10
#define SUBSYSTEM_ID_LENGTH  4

#define ID_MASK		   BIT_MASK(ID_LENGTH)
#define SECURITY_SIZE_MASK BIT_MASK(SECURITY_SIZE_LENGTH)
#define PRIVACY_ID_MASK	   BIT_MASK(PRIVACY_ID_LENGTH)
#define TYPE_ID_MASK	   BIT_MASK(TYPE_ID_LENGTH)
#define SUBSYSTEM_ID_MASK  BIT_MASK(SUBSYSTEM_ID_LENGTH)

#define ID_OFFSET	     0
#define SECURITY_SIZE_OFFSET (ID_OFFSET + ID_LENGTH)
#define PRIVACY_ID_OFFSET    (SECURITY_SIZE_OFFSET + SECURITY_SIZE_LENGTH)
#define TYPE_ID_OFFSET	     (PRIVACY_ID_OFFSET + PRIVACY_ID_LENGTH)
#define SUBSYSTEM_ID_OFFSET  (TYPE_ID_OFFSET + TYPE_ID_LENGTH)

#define SMW_KEYMGR_FORMAT_ID_DEFAULT SMW_KEYMGR_FORMAT_ID_HEX

/**
 * struct smw_keymgr_key_ops - keypair with operations
 * @keys: Public API Keypair
 * @public_data: Get the @pub's public data reference
 * @public_length: Get the @pub's public length reference
 * @private_data: Get the @pub's private data reference
 * @private_length: Get the @pub's private length reference
 *
 * This structure is initialized by the function
 * smw_keymgr_convert_descriptor().
 * The operations are function of the keypair object defined by the
 * key type.
 */
struct smw_keymgr_key_ops {
	struct smw_keypair_buffer *keys;

	unsigned char **(*public_data)(struct smw_keymgr_key_ops *this);
	unsigned int *(*public_length)(struct smw_keymgr_key_ops *this);
	unsigned char **(*private_data)(struct smw_keymgr_key_ops *this);
	unsigned int *(*private_length)(struct smw_keymgr_key_ops *this);
};

static const char *const format_names[] = { [SMW_KEYMGR_FORMAT_ID_HEX] = "HEX",
					    [SMW_KEYMGR_FORMAT_ID_BASE64] =
						    "BASE64" };

/**
 * store_persistent() - Store persistent storage info.
 * @key_attributes: Pointer to smw_keymgr_attributes structure to fill.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- key_attributes is NULL.
 */
static int store_persistent(struct smw_keymgr_attributes *key_attributes);

/**
 * struct smw_keymgr_attributes_tlv - Key manager attribute handler.
 * @type: Attribute type.
 * @verify: Verification function appropriate to the attribute type.
 * @store: Store function appropriate to the attribute type.
 *
 * For an attribute type related to key manager module, this structure provides
 * functions to verify the kind of type (boolean, enumeration, string, numeral)
 * and store the value.
 */
static struct smw_keymgr_attributes_tlv {
	const unsigned char *type;
	int (*verify)(unsigned int length, unsigned char *value);
	int (*store)(struct smw_keymgr_attributes *key_attributes);
} smw_keymgr_attributes_tlv_array[] = {
	{ .type = (const unsigned char *)"PERSISTENT",
	  .verify = smw_tlv_verify_boolean,
	  .store = store_persistent }
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

static int key_id_to_identifier(unsigned long long *id,
				struct smw_keymgr_identifier *identifier)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(identifier);

	if (id) {
		identifier->subsystem_id =
			(*id >> SUBSYSTEM_ID_OFFSET) & SUBSYSTEM_ID_MASK;
		identifier->type_id = (*id >> TYPE_ID_OFFSET) & TYPE_ID_MASK;
		identifier->privacy_id =
			(*id >> PRIVACY_ID_OFFSET) & PRIVACY_ID_MASK;
		identifier->security_size =
			(*id >> SECURITY_SIZE_OFFSET) & SECURITY_SIZE_MASK;
		identifier->id = (*id >> ID_OFFSET) & ID_MASK;

		status = SMW_STATUS_OK;
	}

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

static struct smw_keymgr_key_ops keypair_gen_ops = {
	.keys = NULL,
	.public_data = &public_data_key_gen,
	.public_length = &public_length_key_gen,
	.private_data = &private_data_key_gen,
	.private_length = &private_length_key_gen,
};

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

	if (descriptor->pub) {
		if (!descriptor->pub->buffer)
			return SMW_STATUS_NO_KEY_BUFFER;

		switch (descriptor->identifier.type_id) {
		case SMW_CONFIG_KEY_TYPE_ID_NB:
		case SMW_CONFIG_KEY_TYPE_ID_INVALID:
			break;

		default:
			keypair_gen_ops.keys = descriptor->pub->buffer;
			descriptor->ops = &keypair_gen_ops;
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

	status = key_id_to_identifier(&in->id, &out->identifier);
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

	if (in->id && in->type_name) {
		if (type_id != out->identifier.type_id) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	if (in->id && in->security_size) {
		if (in->security_size != out->identifier.security_size) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	if (!in->id) {
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
}

/**
 * fill_key_attributes() - Fill a smw_keymgr_attributes structure.
 * @type: Attribute type.
 * @value: Attribute value.
 * @value_size: Length of @value in bytes.
 * @key_attributes: Pointer to the key attributes structure to fill.
 *
 * Finds the attribute @type into the key attribute TLV list and if found,
 * verify that value is correct.
 * Then store the attribute value into the @key_attributes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
static int fill_key_attributes(unsigned char *type, unsigned char *value,
			       unsigned int value_size,
			       struct smw_keymgr_attributes *key_attributes)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(smw_keymgr_attributes_tlv_array);
	struct smw_keymgr_attributes_tlv *array =
		smw_keymgr_attributes_tlv_array;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!type || !key_attributes) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	for (i = 0; i < size; i++) {
		if (!SMW_UTILS_STRCMP((char *)type, (char *)array[i].type)) {
			status = array[i].verify(value_size, value);
			if (status != SMW_STATUS_OK)
				break;

			status = array[i].store(key_attributes);
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * read_attributes() - Read key_attributes_list buffer.
 * @attributes_list: List of attributes buffer to read.
 * @attributes_length: Attributes buffer size (bytes).
 * @key_attributes: Pointer to the key attributes structure to fill.
 *
 * This function reads a list of attributes parsed by smw_tlv_read_element()
 * function and fill smw_keymgr_attributes structure using fill_key_attributes()
 * function.
 * @attributes_list is encoded with TLV encoding scheme:
 * The ‘Type’ field is encoded as an ASCII string terminated with the null
 * character.
 * The ‘Length’ field is encoded with two bytes.
 * The ‘Value’ field is a byte stream that contains the data.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 */
static int read_attributes(const unsigned char *attributes_list,
			   unsigned int attributes_length,
			   struct smw_keymgr_attributes *key_attributes)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int value_size = 0;
	unsigned char *type = NULL;
	unsigned char *value = NULL;
	const unsigned char *p = attributes_list;
	const unsigned char *end = attributes_list + attributes_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_attributes)
		goto end;

	/* Initialize key_attributes parameters to default values */
	smw_keymgr_set_default_attributes(key_attributes);

	if (!attributes_list) {
		status = SMW_STATUS_OK;
		goto end;
	}

	while (p < end) {
		/* Parse attribute */
		status = smw_tlv_read_element(&p, end, &type, &value,
					      &value_size);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing attribute failed\n",
				       __func__);
			break;
		}

		/* Fill smw_keymgr_attributes struct */
		status = fill_key_attributes(type, value, value_size,
					     key_attributes);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Bad attribute\n", __func__);
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
generate_key_convert_args(struct smw_generate_key_args *args,
			  struct smw_keymgr_generate_key_args *converted_args,
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
	if (status != SMW_STATUS_OK)
		goto end;

	status = read_attributes(args->key_attributes_list,
				 args->key_attributes_list_length,
				 &converted_args->key_attributes);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
derive_key_convert_args(struct smw_derive_key_args *args,
			struct smw_keymgr_derive_key_args *converted_args,
			enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	struct smw_key_descriptor *key_descriptor_in = args->key_descriptor_in;
	struct smw_key_descriptor *key_descriptor_out =
		args->key_descriptor_out;
	struct smw_keymgr_descriptor *converted_key_descriptor_in =
		&converted_args->key_descriptor_in;
	struct smw_keymgr_descriptor *converted_key_descriptor_out =
		&converted_args->key_descriptor_out;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(key_descriptor_in,
					       converted_key_descriptor_in);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_keymgr_convert_descriptor(key_descriptor_out,
					       converted_key_descriptor_out);
	if (status != SMW_STATUS_OK)
		goto end;

	status = read_attributes(args->key_attributes_list,
				 args->key_attributes_list_length,
				 &converted_args->key_attributes);

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

	status = smw_keymgr_convert_descriptor(args->key_descriptor,
					       &converted_args->key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	status = read_attributes(args->key_attributes_list,
				 args->key_attributes_list_length,
				 &converted_args->key_attributes);

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

	status = read_attributes(args->key_attributes_list,
				 args->key_attributes_list_length,
				 &converted_args->key_attributes);

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

static int store_persistent(struct smw_keymgr_attributes *key_attributes)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (key_attributes) {
		key_attributes->persistent_storage = true;
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

inline unsigned char *
smw_keymgr_get_public_data(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;
	unsigned char *public_data = NULL;

	if (ops)
		public_data = *ops->public_data(ops);

	return public_data;
}

inline unsigned int
smw_keymgr_get_public_length(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;
	unsigned int public_length = 0;

	if (ops)
		public_length = *ops->public_length(ops);

	return public_length;
}

inline unsigned char *
smw_keymgr_get_private_data(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;
	unsigned char *private_data = NULL;

	if (ops)
		private_data = *ops->private_data(ops);

	return private_data;
}

inline unsigned int
smw_keymgr_get_private_length(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;
	unsigned int private_length = 0;

	if (ops)
		private_length = *ops->private_length(ops);

	return private_length;
}

inline void smw_keymgr_set_public_data(struct smw_keymgr_descriptor *descriptor,
				       unsigned char *public_data)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;

	if (ops)
		*ops->public_data(ops) = public_data;
}

inline void
smw_keymgr_set_public_length(struct smw_keymgr_descriptor *descriptor,
			     unsigned int public_length)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;

	if (ops)
		*ops->public_length(ops) = public_length;
}

inline void
smw_keymgr_set_private_data(struct smw_keymgr_descriptor *descriptor,
			    unsigned char *private_data)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;

	if (ops)
		*ops->private_data(ops) = private_data;
}

inline void
smw_keymgr_set_private_length(struct smw_keymgr_descriptor *descriptor,
			      unsigned int private_length)
{
	struct smw_keymgr_key_ops *ops = descriptor->ops;

	if (ops)
		*ops->private_length(ops) = private_length;
}

static void set_key_identifier(struct smw_keymgr_descriptor *descriptor)
{
	struct smw_keymgr_identifier *identifier = &descriptor->identifier;
	unsigned long long *id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(descriptor);

	if (!descriptor->pub)
		return;

	id = &descriptor->pub->id;

	*id = (identifier->id & ID_MASK) << ID_OFFSET;
	*id |= (identifier->security_size & SECURITY_SIZE_MASK)
	       << SECURITY_SIZE_OFFSET;
	*id |= (identifier->privacy_id & PRIVACY_ID_MASK) << PRIVACY_ID_OFFSET;
	*id |= (identifier->type_id & TYPE_ID_MASK) << TYPE_ID_OFFSET;
	*id |= (identifier->subsystem_id & SUBSYSTEM_ID_MASK)
	       << SUBSYSTEM_ID_OFFSET;
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

int smw_keymgr_get_buffers_lengths(enum smw_config_key_type_id type_id,
				   unsigned int security_size,
				   enum smw_keymgr_format_id format_id,
				   unsigned int *public_buffer_length,
				   unsigned int *private_buffer_length)
{
	int status = SMW_STATUS_OK;
	unsigned int public_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	switch (type_id) {
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_NIST:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_R1:
	case SMW_CONFIG_KEY_TYPE_ID_ECDSA_BRAINPOOL_T1:
		public_length = BITS_TO_BYTES_SIZE(security_size) * 2;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_DSA_SM2_FP:
		public_length = 64;
		break;

	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
		public_length = 0;
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown type ID: %d\n", type_id);
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	switch (format_id) {
	case SMW_KEYMGR_FORMAT_ID_HEX:
		break;

	case SMW_KEYMGR_FORMAT_ID_BASE64:
		public_length = smw_utils_get_base64_len(public_length);
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
		*privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
		break;
	case SMW_CONFIG_KEY_TYPE_ID_AES:
	case SMW_CONFIG_KEY_TYPE_ID_DES:
	case SMW_CONFIG_KEY_TYPE_ID_DES3:
	case SMW_CONFIG_KEY_TYPE_ID_SM4:
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

int smw_generate_key(struct smw_generate_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_generate_key_args generate_key_args;
	struct smw_keymgr_descriptor *key_desc;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id type_id;
	unsigned char *public_data;
	unsigned char *private_data;
	unsigned int security_size;
	unsigned int private_length;
	unsigned int public_length;
	unsigned int exp_pub_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	security_size = args->key_descriptor->security_size;

	if (!args->key_descriptor->type_name || !security_size ||
	    args->key_descriptor->id) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = generate_key_convert_args(args, &generate_key_args,
					   &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	key_desc = &generate_key_args.key_descriptor;

	if (args->key_descriptor->buffer) {
		type_id = key_desc->identifier.type_id;
		status = smw_keymgr_get_buffers_lengths(type_id, security_size,
							key_desc->format_id,
							&exp_pub_length, NULL);
		if (status != SMW_STATUS_OK)
			goto end;

		public_data = smw_keymgr_get_public_data(key_desc);
		public_length = smw_keymgr_get_public_length(key_desc);
		private_data = smw_keymgr_get_private_data(key_desc);
		private_length = smw_keymgr_get_private_length(key_desc);

		if ((public_data && public_length < exp_pub_length) ||
		    private_data || private_length) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	}

	status = smw_utils_execute_operation(OPERATION_ID_GENERATE_KEY,
					     &generate_key_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	set_key_identifier(key_desc);
	set_key_buffer_format(key_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_derive_key(struct smw_derive_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_derive_key_args derive_key_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor_in || !args->key_descriptor_out ||
	    !args->key_descriptor_out->type_name ||
	    !args->key_descriptor_out->security_size ||
	    args->key_descriptor_out->id) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = derive_key_convert_args(args, &derive_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_DERIVE_KEY,
					     &derive_key_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_update_key(struct smw_update_key_args *args)
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

int smw_import_key(struct smw_import_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_import_key_args import_key_args;
	struct smw_keymgr_descriptor *key_desc;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	unsigned char *public_data;
	unsigned char *private_data;
	unsigned int private_length;
	unsigned int public_length;

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
	    (private_data && !private_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_IMPORT_KEY,
					     &import_key_args, subsystem_id);

	if (status != SMW_STATUS_OK)
		goto end;

	if (public_data && private_data)
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PAIR;
	else if (public_data)
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PUBLIC;
	else
		/* Only private data is set */
		key_desc->identifier.privacy_id = SMW_KEYMGR_PRIVACY_ID_PRIVATE;

	set_key_identifier(key_desc);
	set_key_buffer_format(key_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_export_key(struct smw_export_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args export_key_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_keymgr_descriptor *key_desc;
	unsigned int security_size;
	enum smw_config_key_type_id type_id;
	unsigned char *public_data;
	unsigned char *private_data;
	unsigned int private_length;
	unsigned int public_length;
	unsigned int exp_pub_length;
	unsigned int exp_priv_length;

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
	    (private_data && !private_length)) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	subsystem_id = key_desc->identifier.subsystem_id;
	security_size = key_desc->identifier.security_size;
	type_id = key_desc->identifier.type_id;
	status = smw_keymgr_get_buffers_lengths(type_id, security_size,
						key_desc->format_id,
						&exp_pub_length,
						&exp_priv_length);
	if (status != SMW_STATUS_OK)
		goto end;

	if ((public_data && public_length < exp_pub_length) ||
	    (private_data && private_length < exp_priv_length)) {
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

int smw_delete_key(struct smw_delete_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_delete_key_args delete_key_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->key_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = delete_key_convert_args(args, &delete_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_DELETE_KEY,
					     &delete_key_args, subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_get_key_buffers_lengths(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_descriptor key_desc = { 0 };
	enum smw_config_key_type_id type_id;
	unsigned int public_length;
	unsigned int private_length;

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

	type_id = key_desc.identifier.type_id;
	status =
		smw_keymgr_get_buffers_lengths(type_id,
					       descriptor->security_size,
					       key_desc.format_id,
					       &public_length, &private_length);
	if (status != SMW_STATUS_OK)
		goto end;

	smw_keymgr_set_public_length(&key_desc, public_length);
	smw_keymgr_set_private_length(&key_desc, private_length);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_get_key_type_name(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier key_identifier;
	const char *name;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = key_id_to_identifier(&descriptor->id, &key_identifier);
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

int smw_get_security_size(struct smw_key_descriptor *descriptor)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_identifier key_identifier;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = key_id_to_identifier(&descriptor->id, &key_identifier);
	if (status != SMW_STATUS_OK)
		goto end;

	descriptor->security_size = key_identifier.security_size;

	if (!key_identifier.security_size)
		status = SMW_STATUS_INVALID_PARAM;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
