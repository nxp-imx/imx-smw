// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
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

/**
 * smw_keymgr_store_persistent() - Store persistent storage info.
 * @key_attributes: Pointer to smw_keymgr_attributes structure to fill.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- key_attributes is NULL.
 */
static int
smw_keymgr_store_persistent(struct smw_keymgr_attributes *key_attributes);

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
	  .store = smw_keymgr_store_persistent }
};

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

	status = smw_config_get_key_type_id(args->key_type_name,
					    &converted_args->key_type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->security_size = args->security_size;
	converted_args->key_attributes_list = args->key_attributes_list;
	converted_args->key_attributes_list_length =
		args->key_attributes_list_length;
	converted_args->key_identifier = args->key_identifier;

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

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (args->version != 0) {
		status = SMW_STATUS_VERSION_NOT_SUPPORTED;
		goto end;
	}

	status =
		smw_config_get_subsystem_id(args->subsystem_name, subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_get_key_type_id(args->key_type_name,
					    &converted_args->key_type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->original_key_identifier = args->original_key_identifier;
	converted_args->security_size = args->security_size;
	converted_args->key_attributes_list = args->key_attributes_list;
	converted_args->key_attributes_list_length =
		args->key_attributes_list_length;
	converted_args->key_identifier = args->key_identifier;

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

	status = smw_config_get_key_type_id(args->key_type_name,
					    &converted_args->key_type_id);
	if (status != SMW_STATUS_OK)
		goto end;

	converted_args->input_buffer = args->input_buffer;
	converted_args->input_buffer_length = args->input_buffer_length;
	converted_args->key_attributes_list = args->key_attributes_list;
	converted_args->key_attributes_list_length =
		args->key_attributes_list_length;
	converted_args->key_identifier = args->key_identifier;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
export_key_convert_args(struct smw_export_key_args *args,
			struct smw_keymgr_export_key_args *converted_args,
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

	converted_args->key_identifier = args->key_identifier;
	converted_args->output_buffer = args->output_buffer;
	converted_args->output_buffer_length = args->output_buffer_length;
	converted_args->key_attributes_list = args->key_attributes_list;
	converted_args->key_attributes_list_length =
		args->key_attributes_list_length;

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

	converted_args->key_identifier = args->key_identifier;
	*subsystem_id = converted_args->key_identifier->subsystem_id;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/**
 * fill_key_attributes() - Fill a smw_keymgr_attributes structure.
 * @type: Attribute type.
 * @value: Attribute value.
 * @value_size: Length of @value in bytes.
 * @key_attributes: Pointer the key attributes structure to fill.
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

	if (!type || !key_attributes)
		goto end;

	for (i = 0; i < size; i++) {
		if (!SMW_UTILS_STRCMP((char *)type, (char *)array[i].type)) {
			status = array[i].verify(value_size, value);
			if (status != SMW_STATUS_OK)
				goto end;

			status = array[i].store(key_attributes);
			break;
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int
smw_keymgr_store_persistent(struct smw_keymgr_attributes *key_attributes)
{
	int status = SMW_STATUS_INVALID_PARAM;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_attributes)
		goto exit;

	key_attributes->persistent_storage = true;
	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_alloc_key_identifier(struct smw_key_identifier **key_identifier)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	*key_identifier = SMW_UTILS_MALLOC(sizeof(struct smw_key_identifier));
	if (!*key_identifier) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_free_key_identifier(struct smw_key_identifier *key_identifier)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!key_identifier) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	SMW_UTILS_FREE(key_identifier);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_generate_key(struct smw_generate_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_generate_key_args generate_key_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = generate_key_convert_args(args, &generate_key_args,
					   &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_GENERATE_KEY,
					     &generate_key_args, subsystem_id);

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

	if (!args) {
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
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = import_key_convert_args(args, &import_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_IMPORT_KEY,
					     &import_key_args, subsystem_id);
end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_export_key(struct smw_export_key_args *args)
{
	int status = SMW_STATUS_OK;

	struct smw_keymgr_export_key_args export_key_args;
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!args) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	status = export_key_convert_args(args, &export_key_args, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_utils_execute_operation(OPERATION_ID_EXPORT_KEY,
					     &export_key_args, subsystem_id);
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

	if (!args) {
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

int smw_keymgr_read_attributes(const unsigned char *attributes_list,
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

	if (!attributes_list || !key_attributes) {
		status = SMW_STATUS_INVALID_PARAM;
		goto exit;
	}

	/* Initialize key_attributes parameter to default values */
	key_attributes->persistent_storage = false;

	while (p < end) {
		/* Parse attribute */
		status = smw_tlv_read_element(&p, end, &type, &value,
					      &value_size);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s: Parsing attribute failed\n",
				       __func__);
			goto exit;
		}

		/* Fill smw_keymgr_attributes struct */
		status = fill_key_attributes(type, value, value_size,
					     key_attributes);
		if (status != SMW_STATUS_OK)
			SMW_DBG_PRINTF(ERROR, "%s: Bad attribute\n", __func__);
	}

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
