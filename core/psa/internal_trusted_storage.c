// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "smw_storage.h"

#include "psa/internal_trusted_storage.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "tlv.h"
#include "object_db.h"

#include "common.h"
#include "util_status.h"

static psa_status_t
set_data_attributes_list(psa_storage_create_flags_t create_flags,
			 unsigned char **attributes_list,
			 unsigned int *attributes_list_length)
{
	unsigned char *p = NULL;
	unsigned int tlv_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*attributes_list = NULL;
	*attributes_list_length = 0;

	if (create_flags & ~PSA_STORAGE_FLAG_WRITE_ONCE)
		return PSA_ERROR_NOT_SUPPORTED;

	if (SMW_TLV_ELEMENT_LENGTH(PERSISTENT_STR, 0, tlv_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (ADD_OVERFLOW(*attributes_list_length, tlv_length,
			 attributes_list_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (create_flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
		if (SMW_TLV_ELEMENT_LENGTH(READ_ONLY_STR, 0, tlv_length))
			return PSA_ERROR_INVALID_ARGUMENT;

		if (ADD_OVERFLOW(*attributes_list_length, tlv_length,
				 attributes_list_length))
			return PSA_ERROR_INVALID_ARGUMENT;
	}

	*attributes_list = SMW_UTILS_MALLOC(*attributes_list_length);
	if (!*attributes_list)
		return PSA_ERROR_INSUFFICIENT_MEMORY;

	p = *attributes_list;

	smw_tlv_set_boolean(&p, PERSISTENT_STR);

	if (create_flags & PSA_STORAGE_FLAG_WRITE_ONCE)
		smw_tlv_set_boolean(&p, READ_ONLY_STR);

	SMW_DBG_ASSERT(*attributes_list_length ==
		       (uintptr_t)p - (uintptr_t)*attributes_list);

	return PSA_SUCCESS;
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
	unsigned char **attributes_list = NULL;
	unsigned int *attributes_list_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

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

	attributes_list = &data_descriptor.attributes_list;
	attributes_list_length = &data_descriptor.attributes_list_length;
	psa_status = set_data_attributes_list(create_flags, attributes_list,
					      attributes_list_length);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	args.subsystem_name = get_psa_default_subsystem();
	args.data_descriptor = &data_descriptor;

	status = smw_store_data(&args);

	if (data_descriptor.attributes_list)
		SMW_UTILS_FREE(data_descriptor.attributes_list);

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

	unsigned int id = INVALID_OBJ_ID;
	union smw_object_db_info info = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!p_info)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (SET_OVERFLOW(uid, id))
		return PSA_ERROR_INVALID_ARGUMENT;

	status =
		smw_object_db_get_info(id, SMW_OBJECT_PERSISTENCE_ID_PERSISTENT,
				       &info);
	if (status == SMW_STATUS_OK) {
		p_info->capacity = info.data_info.size;
		p_info->size = info.data_info.size;
		/* Only PSA_STORAGE_FLAG_WRITE_ONCE is supported for now */
		if (info.data_info.attributes.rw_flags & SMW_STORAGE_READ_ONLY)
			p_info->flags = PSA_STORAGE_FLAG_WRITE_ONCE;

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
