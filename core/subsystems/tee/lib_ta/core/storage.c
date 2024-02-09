// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>

#include "obj.h"
#include "storage.h"
#include "tee_subsystem.h"

TEE_Result storage_store(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exp_param_types = 0;
	bool persistent = false;
	struct obj_data obj_data = { 0 };

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Object ID, persistent
	 * params[1] = Data buffer
	 */
	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	persistent = params[0].value.b ? true : false;

	obj_data.handle = TEE_HANDLE_NULL;
	obj_data.id = params[0].value.a;
	obj_data.data_size = params[1].memref.size;
	obj_data.data = params[1].memref.buffer;

	if (!obj_data.data_size)
		return res;

	if (persistent)
		res = ta_register_persistent_object(&obj_data);
	else
		res = ta_register_transient_object(&obj_data);

	return res;
}

TEE_Result storage_retrieve(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exp_param_types = 0;
	struct obj_data obj_data = { 0 };
	TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	uint32_t id = 0;
	bool persistent = false;
	size_t read_bytes = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Object ID, persistent
	 * params[1] = Data buffer
	 */
	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	id = params[0].value.a;
	persistent = params[0].value.b ? true : false;

	if (persistent) {
		res = ta_find_and_open_persistent_id(id, &obj_handle, true);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get object handle (0x%x)", res);
			return res;
		}

		res = TEE_GetObjectInfo1(obj_handle, &obj_info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get object info (0x%x)", res);
			goto end;
		}

		if (obj_info.dataSize > params[1].memref.size) {
			params[1].memref.size = obj_info.dataSize;
			res = TEE_ERROR_SHORT_BUFFER;
			goto end;
		}

		if (params[1].memref.buffer && obj_info.dataSize) {
			res = TEE_ReadObjectData(obj_handle,
						 params[1].memref.buffer,
						 obj_info.dataSize,
						 &read_bytes);

			if (res != TEE_SUCCESS ||
			    read_bytes != obj_info.dataSize) {
				EMSG("Failed to read data (0x%x), read %zu over %zu",
				     res, read_bytes, obj_info.dataSize);
				goto end;
			}
		}

		/* Return the number of bytes */
		params[1].memref.size = obj_info.dataSize;
	} else {
		res = ta_find_and_get_transient_id(id, &obj_data);

		if (res != TEE_SUCCESS) {
			EMSG("Failed to get object data (0x%x)", res);
			return res;
		}

		if (obj_data.data_size > params[1].memref.size) {
			params[1].memref.size = obj_data.data_size;
			res = TEE_ERROR_SHORT_BUFFER;
			goto end;
		}

		if (params[1].memref.buffer && obj_data.data_size)
			TEE_MemMove(params[1].memref.buffer, obj_data.data,
				    obj_data.data_size);

		/* Return the number of bytes */
		params[1].memref.size = obj_data.data_size;
	}

end:
	if (persistent)
		TEE_CloseObject(obj_handle);

	return res;
}

TEE_Result storage_delete(uint32_t param_types,
			  TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exp_param_types = 0;
	uint32_t id = 0;
	bool persistent = false;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Object ID, persistent
	 */
	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	id = params[0].value.a;
	persistent = params[0].value.b ? true : false;

	if (id) {
		if (persistent)
			res = ta_find_and_delete_persistent_id(id);
		else
			res = ta_find_and_delete_transient_id(id);
	}

	return res;
}

TEE_Result storage_get_data_info(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exp_param_types = 0;
	uint32_t id = 0;
	bool persistent = false;
	size_t data_size = 0;
	TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo obj_info = { 0 };
	struct obj_data obj_data = { 0 };

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Object ID, persistent
	 */
	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				TEE_PARAM_TYPE_VALUE_OUTPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types)
		return res;

	id = params[0].value.a;

	if (!id)
		return res;

	res = ta_get_obj_handle(&obj_handle, id, &persistent);
	if (res != TEE_SUCCESS)
		goto end;

	if (persistent) {
		res = TEE_GetObjectInfo1(obj_handle, &obj_info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get object info (0x%x)", res);
			goto end;
		}

		data_size = obj_info.dataSize;
	} else {
		res = ta_find_and_get_transient_id(id, &obj_data);
		if (res == TEE_SUCCESS)
			data_size = obj_data.data_size;
	}

	params[GET_DATA_INFO_IDX].value.a = persistent ? 1 : 0;

	if (ADD_OVERFLOW(data_size, 0, &params[GET_DATA_INFO_IDX].value.b))
		res = TEE_ERROR_OVERFLOW;

end:
	if (persistent)
		TEE_CloseObject(obj_handle);

	return res;
}
