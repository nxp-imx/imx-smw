// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include "smw_storage.h"

#include "psa/internal_trusted_storage.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "object_db.h"

#include "common.h"
#include "util_status.h"

static psa_status_t
set_data_attributes(psa_storage_create_flags_t create_flags,
		    struct smw_data_attributes *data_attributes)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (create_flags & ~PSA_STORAGE_FLAG_WRITE_ONCE)
		return PSA_ERROR_NOT_SUPPORTED;

	data_attributes->attributes =
		SMW_ATTR_SET_PERSISTENT(data_attributes->attributes);

	if (create_flags & PSA_STORAGE_FLAG_WRITE_ONCE)
		data_attributes->attributes =
			SMW_ATTR_SET_READ_ONLY(data_attributes->attributes);

	return PSA_SUCCESS;
}

static void get_data_attributes(psa_storage_create_flags_t *create_flags,
				smw_attr_attributes_t attributes)
{
	*create_flags = PSA_STORAGE_FLAG_NONE;

	if (SMW_ATTR_IS_READ_ONLY(attributes))
		*create_flags |= PSA_STORAGE_FLAG_WRITE_ONCE;
}

__export psa_status_t psa_its_set(psa_storage_uid_t uid, size_t data_length,
				  const void *p_data,
				  psa_storage_create_flags_t create_flags)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	int status = SMW_STATUS_OK;

	struct psa_storage_info_t info = { 0 };
	struct smw_store_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!p_data)
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status = psa_its_get_info(uid, &info);
	if (psa_status == PSA_SUCCESS) {
		if (info.flags & PSA_STORAGE_FLAG_WRITE_ONCE)
			return PSA_ERROR_NOT_PERMITTED;
	} else if (psa_status != PSA_ERROR_DOES_NOT_EXIST) {
		return psa_status;
	}

	if (SET_OVERFLOW(uid, data_descriptor.identifier))
		return PSA_ERROR_INVALID_ARGUMENT;

	data_descriptor.data = (unsigned char *)p_data;
	if (SET_OVERFLOW(data_length, data_descriptor.length))
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status =
		set_data_attributes(create_flags, &data_descriptor.attributes);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	args.subsystem_name = get_psa_default_subsystem();
	args.data_descriptor = &data_descriptor;

	status = smw_store_data(&args);

	return util_smw_to_psa_status(status);
}

__export psa_status_t psa_its_get(psa_storage_uid_t uid, size_t data_offset,
				  size_t data_size, void *p_data,
				  size_t *p_data_length)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	int status = SMW_STATUS_OK;

	struct smw_retrieve_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };
	unsigned char *data = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!data_size || !p_data || !p_data_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (SET_OVERFLOW(uid, data_descriptor.identifier))
		return PSA_ERROR_INVALID_ARGUMENT;

	args.subsystem_name = get_psa_default_subsystem();
	args.data_descriptor = &data_descriptor;

	if (ADD_OVERFLOW(data_offset, data_size, &data_descriptor.length))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (data_offset) {
		data = SMW_UTILS_MALLOC(data_descriptor.length);
		if (!data)
			return PSA_ERROR_INSUFFICIENT_MEMORY;

		data_descriptor.data = data;
	} else {
		data_descriptor.data = p_data;
	}

	status = smw_retrieve_data(&args);
	if (status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		if (data)
			SMW_UTILS_FREE(data);

		data = SMW_UTILS_MALLOC(data_descriptor.length);
		if (!data)
			return PSA_ERROR_INSUFFICIENT_MEMORY;

		data_descriptor.data = data;

		status = smw_retrieve_data(&args);
		if (status == SMW_STATUS_OUTPUT_TOO_SHORT)
			status = SMW_STATUS_SUBSYSTEM_STORAGE_ERROR;
	}

	if (status != SMW_STATUS_OK)
		goto end;

	if (SUB_OVERFLOW(data_descriptor.length, data_offset, p_data_length)) {
		if (data)
			SMW_UTILS_FREE(data);

		return PSA_ERROR_INVALID_ARGUMENT;
	}

	if (*p_data_length > data_size)
		*p_data_length = data_size;

	if (!*p_data_length) {
		if (data)
			SMW_UTILS_FREE(data);

		return PSA_SUCCESS;
	}

	if (data)
		SMW_UTILS_MEMCPY(p_data, data + data_offset, *p_data_length);

end:
	if (data)
		SMW_UTILS_FREE(data);

	/*
	 * util_smw_to_psa_status() converts SMW_STATUS_UNKNOWN_ID
	 * into PSA_ERROR_INVALID_HANDLE
	 */
	if (status == SMW_STATUS_UNKNOWN_ID)
		return PSA_ERROR_DOES_NOT_EXIST;

	return util_smw_to_psa_status(status);
}

__export psa_status_t psa_its_get_info(psa_storage_uid_t uid,
				       struct psa_storage_info_t *p_info)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	int status = SMW_STATUS_OK;

	struct smw_data_info_args data_info = { 0 };
	struct smw_data_descriptor data_desc = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!p_info)
		return PSA_ERROR_INVALID_ARGUMENT;

	data_info.data_descriptor = &data_desc;
	if (SET_OVERFLOW(uid, data_desc.identifier))
		return PSA_ERROR_INVALID_ARGUMENT;

	status = smw_get_data_info(&data_info);

	if (status == SMW_STATUS_OK) {
		p_info->capacity = data_desc.length;
		p_info->size = data_desc.length;

		get_data_attributes(&p_info->flags,
				    data_desc.attributes.attributes);

		psa_status = PSA_SUCCESS;
	} else if (status == SMW_STATUS_UNKNOWN_ID) {
		psa_status = PSA_ERROR_DOES_NOT_EXIST;
	} else {
		psa_status = util_smw_to_psa_status(status);
	}

	return psa_status;
}

__export psa_status_t psa_its_remove(psa_storage_uid_t uid)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	int status = SMW_STATUS_OK;

	struct psa_storage_info_t info = { 0 };
	struct smw_delete_data_args args = { 0 };
	struct smw_data_descriptor data_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	psa_status = psa_its_get_info(uid, &info);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	if (info.flags & PSA_STORAGE_FLAG_WRITE_ONCE)
		return PSA_ERROR_NOT_PERMITTED;

	if (SET_OVERFLOW(uid, data_descriptor.identifier))
		return PSA_ERROR_INVALID_ARGUMENT;

	args.subsystem_name = get_psa_default_subsystem();
	args.data_descriptor = &data_descriptor;

	status = smw_delete_data(&args);

	return util_smw_to_psa_status(status);
}
