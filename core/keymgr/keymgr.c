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
