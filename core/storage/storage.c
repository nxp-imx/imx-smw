// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include "smw_storage.h"

#include "debug.h"
#include "constants.h"
#include "exec.h"
#include "object_db.h"
#include "storage.h"

static void set_data_identifier(struct smw_storage_data_descriptor *descriptor,
				unsigned int id)
{
	if (descriptor->pub)
		descriptor->pub->identifier = id;
}

static int data_db_create(unsigned int *id,
			  struct smw_storage_data_descriptor *descriptor)
{
	union smw_object_db_info info = { 0 };
	smw_attr_attributes_t attributes =
		descriptor->data_attributes.attributes;

	if (descriptor->subsystem_id == SUBSYSTEM_ID_INVALID)
		info.data_info.subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
	else
		info.data_info.subsystem_name =
			smw_config_get_subsystem_name(descriptor->subsystem_id);

	info.data_info.size = smw_storage_get_data_length(descriptor);
	info.data_info.attributes = attributes;

	return smw_object_db_create(id, attributes, &info);
}

static int data_db_update(struct smw_storage_data_descriptor *descriptor)
{
	union smw_object_db_info info = { 0 };
	unsigned int id = 0;
	smw_attr_attributes_t attributes =
		descriptor->data_attributes.attributes;

	id = smw_storage_get_data_identifier(descriptor);

	if (descriptor->subsystem_id == SUBSYSTEM_ID_INVALID)
		info.data_info.subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
	else
		info.data_info.subsystem_name =
			smw_config_get_subsystem_name(descriptor->subsystem_id);

	info.data_info.size = smw_storage_get_data_length(descriptor);
	info.data_info.attributes = attributes;

	return smw_object_db_update(id, attributes, &info);
}

static int data_db_delete(unsigned int id,
			  struct smw_storage_data_descriptor *descriptor)
{
	smw_attr_attributes_t attributes =
		descriptor->data_attributes.attributes;

	return smw_object_db_delete(id, attributes);
}

static void set_default_attributes(struct smw_data_attributes *data_attributes)
{
	data_attributes->storage_id = 0;
	data_attributes->attributes = 0;

	data_attributes->attributes =
		SMW_ATTR_SET_TRANSIENT(data_attributes->attributes);
}

static int convert_data_descriptor(struct smw_data_descriptor *in,
				   struct smw_storage_data_descriptor *out)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	set_default_attributes(&out->data_attributes);

	if (in->data_attributes)
		out->data_attributes = *in->data_attributes;

	out->pub = in;

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
		if (!args->nb_keys ||
		    args->mode_name == SMW_CIPHER_MODE_NAME_NONE ||
		    !args->keys_desc) {
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
		if (!args->key_descriptor ||
		    args->algo_name == SMW_MAC_ALGO_NAME_NONE) {
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

static int query_subsystem_data(struct smw_storage_data_descriptor *desc)
{
	int status = SMW_STATUS_OK;

	enum subsystem_id subsystem_id = 0;
	enum subsystem_id max_subsystem_id = SUBSYSTEM_ID_NB;
	enum operation_id op_ids[] = { OPERATION_ID_STORAGE_STORE,
				       OPERATION_ID_STORAGE_RETRIEVE };
	enum operation_id op_get_info = OPERATION_ID_STORAGE_IS_DATA_PRESENT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!desc) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	subsystem_id = desc->subsystem_id;

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

	for (; subsystem_id < max_subsystem_id; subsystem_id++) {
		status = smw_config_is_operations_supported(op_ids,
							    ARRAY_SIZE(op_ids),
							    subsystem_id);
		if (status == SMW_STATUS_OPERATION_NOT_SUPPORTED ||
		    status == SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED) {
			status = SMW_STATUS_UNKNOWN_ID;
			continue;
		}

		status = smw_utils_execute_implicit(op_get_info, desc,
						    subsystem_id);
		if (status != SMW_STATUS_UNKNOWN_ID)
			break;
	}

	if (status == SMW_STATUS_OK)
		desc->subsystem_id = subsystem_id;

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
	struct smw_storage_data_descriptor tmp_desc = { 0 };
	enum subsystem_id subsystem_id = 0;
	union smw_object_db_info db_info = { 0 };
	smw_subsystem_t subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
	enum subsystem_id *out_subsystem_id = NULL;

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
					in_desc->data_attributes.attributes,
					&db_info);
	if (status == SMW_STATUS_OK) {
		subsystem_name = db_info.data_info.subsystem_name;

		if (subsystem_id != SUBSYSTEM_ID_INVALID &&
		    smw_config_get_subsystem_name(subsystem_id) !=
			    subsystem_name) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}

		if (out_desc) {
			out_desc->data_attributes.attributes =
				db_info.data_info.attributes;
			smw_storage_set_data_length(out_desc,
						    db_info.data_info.size);

			out_subsystem_id = &out_desc->subsystem_id;
			status = smw_config_get_subsystem_id(subsystem_name,
							     out_subsystem_id);
			if (status != SMW_STATUS_OK)
				goto end;
		}

		goto end;
	} else if (status != SMW_STATUS_UNKNOWN_ID) {
		goto end;
	}

	tmp_desc = *in_desc;
	tmp_desc.pub = &tmp_pub_desc;
	tmp_pub_desc.identifier = data_id;

	status = query_subsystem_data(&tmp_desc);
	if (status == SMW_STATUS_OK) {
		/*
		 * At this stage, the data is not present in the object
		 * database but a subsystem handles it.
		 * Create the input in the object database with attributes
		 * returned by the subsystem.
		 */
		in_desc->subsystem_id = tmp_desc.subsystem_id;

		if (out_desc)
			out_desc->data_attributes = tmp_desc.data_attributes;

		status = data_db_create(&data_id, &tmp_desc);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_new_data_id(struct smw_storage_data_descriptor *desc)
{
	int status = SMW_STATUS_OK;

	unsigned int data_id = INVALID_OBJ_ID;
	unsigned int id = INVALID_OBJ_ID;
	union smw_object_db_info db_info = { 0 };
	struct smw_data_descriptor tmp_pub_desc = { 0 };
	struct smw_storage_data_descriptor tmp_desc = { 0 };
	smw_attr_attributes_t attributes = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* First create a database entry to get an new free object id */
	status = data_db_create(&data_id, desc);
	if (status != SMW_STATUS_OK)
		goto end;

	tmp_desc = *desc;
	tmp_desc.pub = &tmp_pub_desc;
	attributes = desc->data_attributes.attributes;

	for (id = data_id; id < UINT32_MAX; id++) {
		tmp_pub_desc.identifier = id;

		if (id != data_id) {
			status = smw_object_db_get_info(data_id, attributes,
							&db_info);
			if (status == SMW_STATUS_OK)
				continue;
			if (status != SMW_STATUS_UNKNOWN_ID)
				goto end;
		}

		/* Query all subsystems to get if object id is known */
		status = query_subsystem_data(&tmp_desc);
		if (status == SMW_STATUS_UNKNOWN_ID) {
			set_data_identifier(desc, id);
			break;
		} else if (status != SMW_STATUS_OK) {
			goto end;
		}
	}

end:
	if (status != SMW_STATUS_UNKNOWN_ID)
		data_db_delete(data_id, desc);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
store_data_convert_args(struct smw_store_data_args *args,
			struct smw_storage_store_data_args *conv_args)
{
	int status = SMW_STATUS_VERSION_NOT_SUPPORTED;
	unsigned int data_id = INVALID_OBJ_ID;

	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	struct smw_storage_data_descriptor *conv_desc = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0)
		goto end;

	status = smw_config_get_subsystem_id(args->subsystem_name,
					     &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_encryption_args(args->encryption_args,
					 &conv_args->enc_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = convert_sign_args(args->sign_args, &conv_args->sign_args,
				   &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_desc = &conv_args->data_descriptor;
	status = convert_data_descriptor(args->data_descriptor, conv_desc);
	if (status != SMW_STATUS_OK)
		goto end;

	conv_args->data_descriptor.subsystem_id = subsystem_id;

	if (smw_storage_get_data_identifier(conv_desc) == INVALID_OBJ_ID) {
		status = get_new_data_id(conv_desc);
	} else {
		status = find_data(conv_desc, NULL);
		if (status == SMW_STATUS_UNKNOWN_ID) {
			data_id = smw_storage_get_data_identifier(conv_desc);
			status = data_db_create(&data_id, conv_desc);
			if (status != SMW_STATUS_OK)
				goto end;

			/*
			 * Ensure returned status is SMW_STATUS_UNKNOWN_ID to
			 * create the data in the subsystem even if data is
			 * read-only.
			 */
			status = SMW_STATUS_UNKNOWN_ID;
		}
	}
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
	if (status != SMW_STATUS_OK)
		goto end;

	if (subsystem_id == SUBSYSTEM_ID_INVALID)
		conv_args->data_descriptor.subsystem_id = tmp_desc.subsystem_id;

	if (!conv_args->data_descriptor.data_attributes.attributes)
		conv_args->data_descriptor.data_attributes.attributes =
			tmp_desc.data_attributes.attributes;

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
	smw_attr_attributes_t attributes = 0;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->data || !args->data_descriptor->length) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	data_desc = &store_data_args.data_descriptor;

	status = store_data_convert_args(args, &store_data_args);
	if (status == SMW_STATUS_OK) {
		attributes = data_desc->data_attributes.attributes;

		if (SMW_ATTR_IS_READ_ONLY(attributes)) {
			status = SMW_STATUS_INVALID_PARAM;
			goto end;
		}
	} else if (status != SMW_STATUS_UNKNOWN_ID) {
		goto end;
	}

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_STORE,
					     &store_data_args,
					     data_desc->subsystem_id);
	if (status != SMW_STATUS_OK) {
		(void)data_db_delete(smw_storage_get_data_identifier(data_desc),
				     data_desc);
	} else {
		status = data_db_update(data_desc);
	}

end:
	smw_keymgr_free_keys_ptr_array(store_data_args.enc_args.keys_desc,
				       store_data_args.enc_args.nb_keys);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

enum smw_status_code smw_retrieve_data(struct smw_retrieve_data_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_storage_retrieve_data_args retrieve_data_args = { 0 };
	struct smw_storage_data_descriptor *desc = NULL;

	SMW_DBG_TRACE_API_CALL;

	if (!args || !args->data_descriptor) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	if (!args->data_descriptor->identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	desc = &retrieve_data_args.data_descriptor;

	status = retrieve_data_convert_args(args, &retrieve_data_args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_STORAGE_RETRIEVE,
					     &retrieve_data_args,
					     desc->subsystem_id);

	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		status = data_db_update(desc);
		goto end;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	if (SMW_ATTR_IS_READ_ONCE(desc->data_attributes.attributes))
		status = data_db_delete(smw_storage_get_data_identifier(desc),
					desc);

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

	status = data_db_delete(smw_storage_get_data_identifier(data_desc),
				data_desc);

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
		if (args->data_descriptor->data_attributes)
			*args->data_descriptor->data_attributes =
				data_desc->data_attributes;

		status = data_db_update(&data_info_args.data_descriptor);
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
