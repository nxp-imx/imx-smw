// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <util.h>
#include <tee_internal_api.h>

#include "tee_subsystem.h"
#include "cipher.h"
#include "keymgr.h"

#define MAX_CIPHER_KEYS 2

/**
 * struct key_handle - Key handle
 * @handle: Key handle
 * @persistent: Is key a persistent object
 */
struct key_handle {
	TEE_ObjectHandle handle;
	bool persistent;
};

TEE_Result cipher_init(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo key_info;
	struct key_handle keys_handle[MAX_CIPHER_KEYS] = { 0 };
	void *iv = NULL;
	size_t iv_len = 0;
	unsigned int nb_ids = 0;
	unsigned int i;
	uint32_t max_key_size = 0;
	struct shared_context *context;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = TEE Algo ID, TEE Operation
	 * params[1] = Key ids as integer or as integer array
	 * params[2] = IV or none
	 * params[3] = Operation handle
	 */

	if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_MEMREF_INOUT ||
	    params[3].memref.size != sizeof(struct shared_context))
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, 1) == TEE_PARAM_TYPE_VALUE_INPUT) {
		if (params[1].value.a)
			nb_ids++;

		if (params[1].value.b)
			nb_ids++;
	} else {
		/*
		 * If operation with more than two keys is supported, handle
		 * array of ids here
		 */
		return res;
	}

	if (TEE_PARAM_TYPE_GET(param_types, 2) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		iv = params[2].memref.buffer;
		iv_len = params[2].memref.size;
	} else if (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_NONE) {
		return res;
	}

	/* Get key(s) handle and max key size */
	res = ta_get_key_handle(&keys_handle[0].handle, params[1].value.a,
				&keys_handle[0].persistent);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key handle (0x%x)", res);
		goto end;
	}

	res = TEE_GetObjectInfo1(keys_handle[0].handle, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key info (0x%x)", res);
		goto end;
	}

	max_key_size = key_info.maxKeySize;

	if (nb_ids == 2) {
		res = ta_get_key_handle(&keys_handle[1].handle,
					params[1].value.b,
					&keys_handle[1].persistent);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key handle (0x%x)", res);
			goto end;
		}

		res = TEE_GetObjectInfo1(keys_handle[1].handle, &key_info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get key info (0x%x)", res);
			goto end;
		}

		max_key_size = MAX(max_key_size, key_info.maxKeySize);
		max_key_size *= 2;
	}

	/*
	 * Allocate operation.
	 * If cipher initialization succeed it's freed during update or final
	 * step
	 */
	res = TEE_AllocateOperation(&op_handle, params[0].value.a,
				    params[0].value.b, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation (0x%x)", res);
		goto end;
	}

	/* Set operation key(s) */
	if (nb_ids == 1)
		res = TEE_SetOperationKey(op_handle, keys_handle[0].handle);
	else if (nb_ids == 2)
		res = TEE_SetOperationKey2(op_handle, keys_handle[0].handle,
					   keys_handle[1].handle);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to set operation key(s)");
		TEE_FreeOperation(op_handle);
		goto end;
	}

	/* Cipher initialization */
	TEE_CipherInit(op_handle, iv, iv_len);

	/* Share operation handle */
	context = params[3].memref.buffer;
	context->handle = op_handle;

end:
	/* Close persistent key(s) opened */
	for (i = 0; i < nb_ids; i++) {
		if (keys_handle[i].handle && keys_handle[i].persistent)
			TEE_CloseObject(keys_handle[i].handle);
	}

	return res;
}

TEE_Result cipher_update(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle;
	uint32_t exp_param_types = 0;
	struct shared_context *context;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = None
	 */
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE);
	if (exp_param_types != param_types)
		return res;

	context = params[0].memref.buffer;
	op_handle = context->handle;

	res = TEE_CipherUpdate(op_handle, params[1].memref.buffer,
			       params[1].memref.size, params[2].memref.buffer,
			       &params[2].memref.size);

	return res;
}

TEE_Result cipher_final(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle;
	uint32_t exp_param_types = 0;
	struct shared_context *context;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = None
	 */
	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_INPUT,
					  TEE_PARAM_TYPE_MEMREF_OUTPUT,
					  TEE_PARAM_TYPE_NONE);
	if (exp_param_types != param_types)
		return res;

	context = params[0].memref.buffer;
	op_handle = context->handle;

	res = TEE_CipherDoFinal(op_handle, params[1].memref.buffer,
				params[1].memref.size, params[2].memref.buffer,
				&params[2].memref.size);

	if (res == TEE_SUCCESS)
		TEE_FreeOperation(op_handle);

	return res;
}
