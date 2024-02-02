// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw_storage.h"

#include "debug.h"
#include "constants.h"
#include "utils.h"
#include "exec.h"
#include "tlv.h"
#include "attr.h"
#include "object_db.h"
#include "storage.h"
#include "lifecycle.h"

static int data_db_create(struct smw_storage_data_descriptor *descriptor)
{
	union smw_object_db_info info = { 0 };
	unsigned int id = 0;
	enum smw_object_persistence_id persistence_id =
		SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;

	id = smw_storage_get_data_identifier(descriptor);
	info.data_info.subsystem_id = descriptor->subsystem_id;
	info.data_info.size = smw_storage_get_data_length(descriptor);
	info.data_info.attributes = descriptor->attributes;
	persistence_id = descriptor->attributes.persistence_id;

	return smw_object_db_create(&id, persistence_id, &info);
}

static int data_db_update(struct smw_storage_data_descriptor *descriptor)
{
	union smw_object_db_info info = { 0 };
	unsigned int id = 0;
	enum smw_object_persistence_id persistence_id =
		SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;

	id = smw_storage_get_data_identifier(descriptor);
	info.data_info.subsystem_id = descriptor->subsystem_id;
	info.data_info.size = smw_storage_get_data_length(descriptor);
	info.data_info.attributes = descriptor->attributes;
	persistence_id = descriptor->attributes.persistence_id;

	return smw_object_db_update(id, persistence_id, &info);
}

static int data_db_delete(struct smw_storage_data_descriptor *descriptor)
{
	unsigned int id = 0;
	enum smw_object_persistence_id persistence_id =
		SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;

	id = smw_storage_get_data_identifier(descriptor);
	persistence_id = descriptor->attributes.persistence_id;

	return smw_object_db_delete(id, persistence_id);
}

/**
 * store_read_only() - Store read-only attribute.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to the storage ID value.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_read_only(void *attributes, unsigned char *value,
			   unsigned int length);

/**
 * store_read_once() - Store read-once attribute.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to the storage ID value.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_read_once(void *attributes, unsigned char *value,
			   unsigned int length);

/**
 * store_lifecycle() - Store lifecycle attribute.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to the lifecycle.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_lifecycle(void *attributes, unsigned char *value,
			   unsigned int length);

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

#define RW_FLAG(_name)                                                         \
	{                                                                      \
		.rw_str = _name##_STR, .flag = SMW_STORAGE_##_name,            \
	}

static const struct rw_info {
	const char *rw_str;
	unsigned int flag;
} rw_info[] = { RW_FLAG(READ_ONLY), RW_FLAG(READ_ONCE) };

static const char *get_rw_flag_str(unsigned int id)
{
	const char *str = NULL;
	unsigned int i = 0;

	for (; id && i < ARRAY_SIZE(rw_info); i++) {
		if (id == rw_info[i].flag) {
			str = rw_info[i].rw_str;
			break;
		}
	}

	return str;
}

static const struct attribute_tlv data_attributes_tlv_array[] = {
	{ .type = (const unsigned char *)READ_ONLY_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_read_only },
	{ .type = (const unsigned char *)READ_ONCE_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_read_once },
	{ .type = (const unsigned char *)LIFECYCLE_STR,
	  .verify = smw_tlv_verify_variable_length_list,
	  .store = store_lifecycle },
	{ .type = (const unsigned char *)PERSISTENT_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_persistent }
};

static int store_read_only(void *attributes, unsigned char *value,
			   unsigned int length)
{
	(void)value;
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_storage_data_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->rw_flags |= SMW_STORAGE_READ_ONLY;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_read_once(void *attributes, unsigned char *value,
			   unsigned int length)
{
	(void)value;
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_storage_data_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->rw_flags |= SMW_STORAGE_READ_ONCE;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int set_data_rw_flags(unsigned char **attrs, unsigned int *attrs_len,
			     struct smw_storage_data_attributes *in_attrs)
{
	int status = SMW_STATUS_INVALID_PARAM;
	const char *attr = NULL;
	unsigned char *p = NULL;
	unsigned int last_attr_off = 0;
	unsigned int add_len = 0;
	unsigned long flags = 0;
	unsigned long flag_mask = BIT(0);

	if (!in_attrs || !attrs || !attrs_len)
		goto exit;

	flags = in_attrs->rw_flags;
	while (flags) {
		if (!(flags & flag_mask)) {
			flag_mask <<= 1;
			continue;
		}

		attr = get_rw_flag_str(flags & flag_mask);

		if (attr) {
			if (SMW_TLV_ELEMENT_LENGTH(attr, 0, add_len)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto exit;
			}

			last_attr_off = *attrs_len;

			if (INC_OVERFLOW(*attrs_len, add_len)) {
				status = SMW_STATUS_OPERATION_FAILURE;
				goto exit;
			}

			*attrs = SMW_UTILS_REALLOC(*attrs, *attrs_len);
			if (!*attrs) {
				status = SMW_STATUS_ALLOC_FAILURE;
				goto exit;
			}

			p = *attrs;
			p += last_attr_off;

			smw_tlv_set_boolean(&p, attr);
		}

		CLEAR_BITS(flags, flag_mask);
		flag_mask <<= 1;
	}

	status = SMW_STATUS_OK;

exit:
	return status;
}

static int store_lifecycle(void *attributes, unsigned char *value,
			   unsigned int length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_storage_data_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr && value && length)
		status = smw_lifecycle_get_tlv(&attr->lifecycle_flags, value,
					       length);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_persistent(void *attributes, unsigned char *value,
			    unsigned int length)
{
	(void)value;
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_storage_data_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->persistence_id = SMW_OBJECT_PERSISTENCE_ID_PERSISTENT;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void
set_default_attributes(struct smw_storage_data_attributes *data_attributes)
{
	data_attributes->rw_flags = 0;
	data_attributes->lifecycle_flags = 0;
	data_attributes->persistence_id = SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;
}

static int convert_data_descriptor(struct smw_data_descriptor *in,
				   struct smw_storage_data_descriptor *out)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Initialize data attributes parameters to default values */
	set_default_attributes(&out->attributes);

	status =
		read_attributes(in->attributes_list, in->attributes_list_length,
				&out->attributes, data_attributes_tlv_array,
				ARRAY_SIZE(data_attributes_tlv_array));
	if (status != SMW_STATUS_OK)
		goto end;

	out->pub = in;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int convert_encryption_args(struct smw_encryption_args *args,
				   struct smw_storage_enc_args *converted_args,
				   enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;
	struct smw_keymgr_descriptor ***keys_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	converted_args->mode_id = SMW_CONFIG_CIPHER_MODE_ID_INVALID;

	if (args) {
		if (!args->nb_keys || !args->mode_name || !args->keys_desc) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		status = smw_utils_get_cipher_mode_id(args->mode_name,
						      &converted_args->mode_id);
		if (status != SMW_STATUS_OK)
			goto end;

		converted_args->nb_keys = args->nb_keys;
		keys_desc = &converted_args->keys_desc;

		status =
			smw_keymgr_convert_descriptors(args->keys_desc,
						       keys_desc, args->nb_keys,
						       subsystem_id);

		converted_args->pub = args;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int convert_sign_args(struct smw_sign_args *args,
			     struct smw_storage_sign_args *converted_args,
			     enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;
	struct smw_keymgr_descriptor *key_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	converted_args->key_descriptor.identifier.type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	converted_args->algo_id = SMW_CONFIG_MAC_ALGO_ID_INVALID;

	if (args) {
		if (!args->key_descriptor || !args->algo_name) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		key_desc = &converted_args->key_descriptor;

		status = smw_keymgr_convert_descriptor(args->key_descriptor,
						       key_desc, false,
						       subsystem_id);
		if (status != SMW_STATUS_OK)
			goto end;

		status = smw_utils_get_mac_algo_id(args->algo_name,
						   &converted_args->algo_id);
		if (status != SMW_STATUS_OK)
			goto end;

		status = smw_utils_get_hash_algo_id(args->hash_name,
						    &converted_args->hash_id);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int find_data(struct smw_storage_data_descriptor *in_desc,
		     struct smw_storage_data_descriptor *out_desc)
{
	int status = SMW_STATUS_OK;

	unsigned int data_id = 0;
	struct smw_data_descriptor tmp_pub_desc = { 0 };
	struct smw_storage_data_descriptor data_desc = { 0 };
	enum subsystem_id subsystem_id = 0;
	enum subsystem_id max_subsystem_id = SUBSYSTEM_ID_NB;
	enum operation_id op_ids[] = { OPERATION_ID_STORAGE_STORE,
				       OPERATION_ID_STORAGE_RETRIEVE };
	enum operation_id op_get_info = OPERATION_ID_STORAGE_IS_DATA_PRESENT;
	union smw_object_db_info db_info = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!in_desc) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	subsystem_id = in_desc->subsystem_id;

	data_id = smw_storage_get_data_identifier(in_desc);
	if (!data_id) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/*
	 * First, parse the object database to check if the data identifier
	 * is present.
	 * If data is not present in the object data try to find it in
	 * a subsystem supporting one data storage operation.
	 */
	status = smw_object_db_get_info(data_id,
					in_desc->attributes.persistence_id,
					&db_info);
	if (status == SMW_STATUS_OK) {
		if (subsystem_id != SUBSYSTEM_ID_INVALID &&
		    subsystem_id != db_info.data_info.subsystem_id) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		if (out_desc) {
			out_desc->attributes = db_info.data_info.attributes;
			smw_storage_set_data_length(out_desc,
						    db_info.data_info.size);
			out_desc->subsystem_id = db_info.data_info.subsystem_id;
		}

		goto end;
	} else if (status != SMW_STATUS_UNKNOWN_ID) {
		goto end;
	}

	/*
	 * If the subsystem is not specified, try to get data information
	 * querying each subsystem supporting either store or retrieve data.
	 */
	if (subsystem_id == SUBSYSTEM_ID_INVALID) {
		subsystem_id = 0;
	} else if (subsystem_id < SUBSYSTEM_ID_NB) {
		max_subsystem_id = subsystem_id + 1;
	} else {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	/*
	 * Set temporary public data descriptor in order to execute the
	 * subsystem operation to find if data is present or not.
	 */
	data_desc.pub = &tmp_pub_desc;
	data_desc.attributes.persistence_id =
		in_desc->attributes.persistence_id;
	tmp_pub_desc.identifier = data_id;

	for (; subsystem_id < max_subsystem_id; subsystem_id++) {
		status = smw_config_is_operations_supported(op_ids,
							    ARRAY_SIZE(op_ids),
							    subsystem_id);
		if (status == SMW_STATUS_OPERATION_NOT_SUPPORTED ||
		    status == SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED) {
			status = SMW_STATUS_UNKNOWN_ID;
			continue;
		}

		status = smw_utils_execute_implicit(op_get_info, &data_desc,
						    subsystem_id);
		if (status != SMW_STATUS_UNKNOWN_ID)
			break;
	}

	if (status == SMW_STATUS_OK) {
		/*
		 * At this stage, the data is not present in the object
		 * database but a subsystem handles it.
		 * Create the input in the object database with attributes
		 * returned by the subsystem.
		 */
		in_desc->subsystem_id = subsystem_id;

		status = data_db_create(&data_desc);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
store_data_convert_args(struct smw_store_data_args *args,
			struct smw_storage_store_data_args *converted_args)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_encryption_args(args->encryption_args,
					 &converted_args->enc_args,
					 &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_sign_args(args->sign_args, &converted_args->sign_args,
				   &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &converted_args->data_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->data_descriptor.subsystem_id = subsystem_id;

	status = find_data(&converted_args->data_descriptor, NULL);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
retrieve_data_convert_args(struct smw_retrieve_data_args *args,
			   struct smw_storage_retrieve_data_args *conv_args)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_storage_data_descriptor tmp_desc = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &conv_args->data_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_args->data_descriptor.subsystem_id = subsystem_id;

	status = find_data(&conv_args->data_descriptor, &tmp_desc);
	if (status == SMW_STATUS_OK && subsystem_id == SUBSYSTEM_ID_INVALID)
		conv_args->data_descriptor.subsystem_id = tmp_desc.subsystem_id;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
delete_data_convert_args(struct smw_delete_data_args *args,
			 struct smw_storage_delete_data_args *converted_args)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &converted_args->data_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->data_descriptor.subsystem_id = subsystem_id;

	status = find_data(&converted_args->data_descriptor,
			   &converted_args->data_descriptor);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
data_info_convert_args(struct smw_data_info_args *args,
		       struct smw_storage_data_info_args *converted_args)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &converted_args->data_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->data_descriptor.subsystem_id = subsystem_id;

	status = find_data(&converted_args->data_descriptor,
			   &converted_args->data_descriptor);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int data_info_set_attributes(struct smw_data_info_args *pub,
				    struct smw_storage_data_descriptor *desc)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_data_attributes *in_attrs = NULL;
	unsigned char *attrs = NULL;
	unsigned int attrs_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	in_attrs = &desc->attributes;

	pub->lifecycle_list_length = 0;
	pub->lifecycle_list = NULL;
	status = smw_lifecycle_set_tlv(&pub->lifecycle_list,
				       &pub->lifecycle_list_length,
				       in_attrs->lifecycle_flags);
	if (status != SMW_STATUS_OK)
		goto exit;

	pub->persistence =
		smw_object_get_persistence_name(in_attrs->persistence_id);

	status = set_data_rw_flags(&attrs, &attrs_length, in_attrs);
	if (status != SMW_STATUS_OK)
		goto exit;

	desc->pub->attributes_list = attrs;
	desc->pub->attributes_list_length = attrs_length;

exit:
	if (status != SMW_STATUS_OK) {
		if (attrs)
			SMW_UTILS_FREE(attrs);

		if (pub->lifecycle_list) {
			SMW_UTILS_FREE(pub->lifecycle_list);
			pub->lifecycle_list = NULL;
			pub->lifecycle_list_length = 0;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

inline unsigned int
smw_storage_get_data_identifier(struct smw_storage_data_descriptor *descriptor)
{
	unsigned int identifier = 0;

	if (descriptor->pub)
		identifier = descriptor->pub->identifier;

	return identifier;
}

inline unsigned char *
smw_storage_get_data(struct smw_storage_data_descriptor *descriptor)
{
	unsigned char *data = NULL;

	if (descriptor->pub)
		data = descriptor->pub->data;

	return data;
}

inline unsigned int
smw_storage_get_data_length(struct smw_storage_data_descriptor *descriptor)
{
	unsigned int length = 0;

	if (descriptor->pub)
		length = descriptor->pub->length;

	return length;
}

inline void
smw_storage_set_data_length(struct smw_storage_data_descriptor *descriptor,
			    unsigned int length)
{
	if (descriptor->pub)
		descriptor->pub->length = length;
}

inline unsigned char *smw_storage_get_iv(struct smw_storage_enc_args *enc_args)
{
	unsigned char *iv = NULL;

	if (enc_args->pub)
		iv = enc_args->pub->iv;

	return iv;
}

inline unsigned int
smw_storage_get_iv_length(struct smw_storage_enc_args *enc_args)
{
	unsigned int length = 0;

	if (enc_args->pub)
		length = enc_args->pub->iv_length;

	return length;
}

enum smw_status_code smw_store_data(struct smw_store_data_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_store_data_args store_data_args = { 0 };
	struct smw_storage_data_descriptor *data_desc = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->identifier ||
	    !args->data_descriptor->data || !args->data_descriptor->length) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	data_desc = &store_data_args.data_descriptor;

	status = store_data_convert_args(args, &store_data_args);
	if (status == SMW_STATUS_OK) {
		if (data_desc->attributes.rw_flags & SMW_STORAGE_READ_ONLY) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	} else if (status == SMW_STATUS_UNKNOWN_ID) {
		status = data_db_create(data_desc);
		if (status != SMW_STATUS_OK)
			goto end;
	} else {
		goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_STORE,
					     &store_data_args,
					     data_desc->subsystem_id);
	if (status != SMW_STATUS_OK)
		(void)data_db_delete(data_desc);
	else
		status = data_db_update(data_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_retrieve_data(struct smw_retrieve_data_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_retrieve_data_args retrieve_data_args = { 0 };
	struct smw_storage_data_descriptor *data_desc = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	data_desc = &retrieve_data_args.data_descriptor;

	status = retrieve_data_convert_args(args, &retrieve_data_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_RETRIEVE,
					     &retrieve_data_args,
					     data_desc->subsystem_id);

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		status = data_db_update(data_desc);
		goto end;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	if (data_desc->attributes.rw_flags & SMW_STORAGE_READ_ONCE)
		status = data_db_delete(data_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_delete_data(struct smw_delete_data_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_delete_data_args delete_data_args = { 0 };
	struct smw_storage_data_descriptor *data_desc = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args || !args->data_descriptor->identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	data_desc = &delete_data_args.data_descriptor;

	status = delete_data_convert_args(args, &delete_data_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_DELETE,
					     &delete_data_args,
					     data_desc->subsystem_id);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_UNKNOWN_ID)
		goto end;

	status = data_db_delete(data_desc);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_get_data_info(struct smw_data_info_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_data_info_args data_info_args = { 0 };
	struct smw_storage_data_descriptor *data_desc = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (args->data_descriptor->data) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	data_desc = &data_info_args.data_descriptor;

	status = data_info_convert_args(args, &data_info_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_implicit(OPERATION_ID_STORAGE_GET_DATA_INFO,
					    data_desc, data_desc->subsystem_id);
	if (status == SMW_STATUS_OK) {
		status = data_info_set_attributes(args, data_desc);
		if (status == SMW_STATUS_OK)
			status =
				data_db_update(&data_info_args.data_descriptor);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
