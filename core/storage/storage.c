// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
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
 * store_write_only() - Store write-only attribute.
 * @attributes: Pointer to attribute structure to fill.
 * @value: Pointer to the storage ID value.
 * @length: Length of @value in bytes.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- @attributes is NULL.
 */
static int store_write_only(void *attributes, unsigned char *value,
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

static const struct attribute_tlv data_attributes_tlv_array[] = {
	{ .type = (const unsigned char *)READ_ONLY_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_read_only },
	{ .type = (const unsigned char *)READ_ONCE_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_read_once },
	{ .type = (const unsigned char *)WRITE_ONLY_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_write_only },
	{ .type = (const unsigned char *)LIFECYCLE_STR,
	  .verify = smw_tlv_verify_variable_length_list,
	  .store = store_lifecycle },
	{ .type = (const unsigned char *)PERSISTENT_STR,
	  .verify = smw_tlv_verify_boolean,
	  .store = store_persistent }
};

#define LIFECYCLE(_name)                                                       \
	{                                                                      \
		.lifecycle_str = LC_##_name##_STR,                             \
		.lifecycle = SMW_LIFECYCLE_##_name,                            \
	}

/**
 * struct - Lifecycle
 * @lifecycle_str: Lifecycle name used for TLV encoding.
 * @lifecycle: Lifecycle id.
 */
static const struct {
	const char *lifecycle_str;
	unsigned int lifecycle;
} lifecycle_info[] = { LIFECYCLE(OPEN), LIFECYCLE(CLOSED),
		       LIFECYCLE(CLOSED_LOCKED), LIFECYCLE(CURRENT) };

static unsigned int get_lifecycle(const char *name)
{
	unsigned int lifecycle = 0;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(lifecycle_info); i++) {
		if (!SMW_UTILS_STRCMP(name, lifecycle_info[i].lifecycle_str)) {
			lifecycle = lifecycle_info[i].lifecycle;
			break;
		}
	}

	return lifecycle;
}

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

static int store_write_only(void *attributes, unsigned char *value,
			    unsigned int length)
{
	(void)value;
	(void)length;

	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_storage_data_attributes *attr = attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr) {
		attr->rw_flags |= SMW_STORAGE_WRITE_ONLY;
		status = SMW_STATUS_OK;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_lifecycle(void *attributes, unsigned char *value,
			   unsigned int length)
{
	int status = SMW_STATUS_INVALID_PARAM;
	struct smw_storage_data_attributes *attr = attributes;
	const unsigned char *p = value;
	const unsigned char *p_end = value + length;
	const char *lifecycle = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (attr && value && length) {
		while (p < p_end) {
			lifecycle = (const char *)p;

			p += SMW_UTILS_STRLEN(lifecycle) + 1;

			if (p > p_end) {
				SMW_DBG_PRINTF(ERROR,
					       "%s Parsing lifecycle failed\n",
					       __func__);
				goto end;
			}

			attr->lifecycle_flags |= get_lifecycle(lifecycle);
		}

		if (attr->lifecycle_flags)
			status = SMW_STATUS_OK;
	}

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
				   struct smw_storage_data_descriptor *out,
				   enum subsystem_id *subsystem_id,
				   union smw_object_db_info *info)
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

	status = smw_object_db_get_info(in->identifier,
					out->attributes.persistence_id, info);
	if (status == SMW_STATUS_OK) {
		if (*subsystem_id != SUBSYSTEM_ID_INVALID &&
		    info->data_info.subsystem_id != *subsystem_id) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		*subsystem_id = info->data_info.subsystem_id;
	} else if (status != SMW_STATUS_UNKNOWN_ID) {
		goto end;
	}

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
			     enum subsystem_id subsystem_id)
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

static int
store_data_convert_args(struct smw_store_data_args *args,
			struct smw_storage_store_data_args *converted_args,
			enum subsystem_id *subsystem_id,
			union smw_object_db_info *info)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_encryption_args(args->encryption_args,
					 &converted_args->enc_args,
					 subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_sign_args(args->sign_args, &converted_args->sign_args,
				   *subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &converted_args->data_descriptor,
					 subsystem_id, info);
end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
retrieve_data_convert_args(struct smw_retrieve_data_args *args,
			   struct smw_storage_retrieve_data_args *conv_args,
			   enum subsystem_id *subsystem_id,
			   union smw_object_db_info *info)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &conv_args->data_descriptor,
					 subsystem_id, info);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
delete_data_convert_args(struct smw_delete_data_args *args,
			 struct smw_storage_delete_data_args *converted_args,
			 enum subsystem_id *subsystem_id,
			 union smw_object_db_info *info)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_data_descriptor(args->data_descriptor,
					 &converted_args->data_descriptor,
					 subsystem_id, info);

end:
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
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	union smw_object_db_info info = { 0 };
	enum smw_object_persistence_id persistence_id =
		SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->identifier ||
	    !args->data_descriptor->data || !args->data_descriptor->length) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = store_data_convert_args(args, &store_data_args, &subsystem_id,
					 &info);

	persistence_id =
		store_data_args.data_descriptor.attributes.persistence_id;

	if (status == SMW_STATUS_OK) {
		if (info.data_info.attributes.rw_flags &
		    SMW_STORAGE_READ_ONLY) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	} else if (status == SMW_STATUS_UNKNOWN_ID) {
		status =
			smw_object_db_create(&args->data_descriptor->identifier,
					     persistence_id, &info);
		if (status != SMW_STATUS_OK)
			goto end;
	} else {
		goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_STORE,
					     &store_data_args, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	info.data_info.size = store_data_args.data_descriptor.pub->length;
	info.data_info.attributes = store_data_args.data_descriptor.attributes;
	status = smw_object_db_update(args->data_descriptor->identifier,
				      persistence_id, &info);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_retrieve_data(struct smw_retrieve_data_args *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;

	struct smw_storage_retrieve_data_args retrieve_data_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	union smw_object_db_info info = { 0 };
	bool obj_not_present = false;
	enum smw_object_persistence_id persistence_id =
		SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = retrieve_data_convert_args(args, &retrieve_data_args,
					    &subsystem_id, &info);
	if (status == SMW_STATUS_UNKNOWN_ID) {
		if (subsystem_id == SUBSYSTEM_ID_INVALID)
			goto end;

		obj_not_present = true;
	} else if (status != SMW_STATUS_OK) {
		goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_RETRIEVE,
					     &retrieve_data_args, subsystem_id);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_UNKNOWN_ID)
		goto end;

	if (obj_not_present)
		goto end;

	persistence_id = info.data_info.attributes.persistence_id;

	if (status != SMW_STATUS_OK ||
	    info.data_info.attributes.rw_flags & SMW_STORAGE_READ_ONCE) {
		tmp_status =
			smw_object_db_delete(args->data_descriptor->identifier,
					     persistence_id);

		if (status == SMW_STATUS_OK ||
		    info.data_info.attributes.persistence_id !=
			    SMW_OBJECT_PERSISTENCE_ID_TRANSIENT)
			status = tmp_status;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_delete_data(struct smw_delete_data_args *args)
{
	int status = SMW_STATUS_OK;
	int tmp_status = SMW_STATUS_OK;
	enum smw_object_persistence_id persistence_id =
		SMW_OBJECT_PERSISTENCE_ID_TRANSIENT;

	struct smw_storage_delete_data_args delete_data_args = { 0 };
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	union smw_object_db_info info = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args || !args->data_descriptor->identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = delete_data_convert_args(args, &delete_data_args,
					  &subsystem_id, &info);
	if (status != SMW_STATUS_OK)
		goto end;

	persistence_id = info.data_info.attributes.persistence_id;

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_DELETE,
					     &delete_data_args, subsystem_id);
	if (status != SMW_STATUS_OK && status != SMW_STATUS_UNKNOWN_ID)
		goto end;

	tmp_status = smw_object_db_delete(args->data_descriptor->identifier,
					  persistence_id);

	if (status == SMW_STATUS_OK ||
	    info.data_info.attributes.persistence_id !=
		    SMW_OBJECT_PERSISTENCE_ID_TRANSIENT)
		status = tmp_status;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
