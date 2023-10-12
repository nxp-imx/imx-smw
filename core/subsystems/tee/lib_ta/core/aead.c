// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <util.h>

#include "common.h"
#include "tee_subsystem.h"
#include "aead.h"
#include "keymgr.h"

TEE_Result aead_init(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo key_info = { 0 };
	struct key_handle key_handle = { 0 };
	uint32_t max_key_size = 0;
	struct shared_context *context = NULL;
	struct aead_shared_params *shared_params = NULL;
	void *iv = NULL;
	size_t iv_len = 0;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = IV
	 * params[1] = Key ids as integer or as integer array
	 * params[2] = Pointer to aead_shared_params structure
	 * params[3] = Operation handle
	 */

	if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT ||
	    TEE_PARAM_TYPE_GET(param_types, 3) != TEE_PARAM_TYPE_MEMREF_INOUT ||
	    params[3].memref.size != sizeof(*context) ||
	    !params[3].memref.buffer)
		return res;

	if (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_VALUE_INPUT)
		return res;

	if ((TEE_PARAM_TYPE_GET(param_types, 2) !=
	     TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[2].memref.size != sizeof(*shared_params) ||
	    !params[2].memref.buffer)
		return res;

	shared_params = params[2].memref.buffer;

	/* Get key handle */
	res = ta_get_key_handle(&key_handle.handle, params[1].value.a,
				&key_handle.persistent);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key handle (0x%x)", res);
		goto end;
	}

	/* Get max key size */
	res = TEE_GetObjectInfo1(key_handle.handle, &key_info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get key info (0x%x)", res);
		goto end;
	}

	max_key_size = key_info.maxObjectSize;

	/*
	 * Allocate operation.
	 * If AE initialization succeeds, it's freed during update or final
	 * step
	 */
	res = TEE_AllocateOperation(&op_handle, shared_params->aead_algo,
				    shared_params->aead_op, max_key_size);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation (0x%x)", res);
		goto end;
	}

	res = check_operation_keys_usage(op_handle, &key_info, 1);
	if (res)
		goto end;

	res = TEE_SetOperationKey(op_handle, key_handle.handle);
	if (res == TEE_SUCCESS) {
		/* AE initialization */
		iv = params[0].memref.buffer;
		iv_len = params[0].memref.size;

		res = TEE_AEInit(op_handle, iv, iv_len, shared_params->tag_len,
				 shared_params->aad_len,
				 shared_params->payload_len);
		if (res == TEE_SUCCESS) {
			/* Share operation handle */
			context = params[3].memref.buffer;
			context->handle = op_handle;
		}
	}

end:
	if (res != TEE_SUCCESS)
		TEE_FreeOperation(op_handle);

	/* Close opened persistent key */
	if (key_handle.handle && key_handle.persistent)
		TEE_CloseObject(key_handle.handle);

	FMSG("Return status of %s = 0x%x", __func__, res);

	return res;
}

TEE_Result aead_update_aad(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	struct shared_context *context = NULL;
	void *aad = NULL;
	size_t aad_len = 0;

	FMSG("Executing..... %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = AAD data
	 * params[2] = None
	 * params[3] = None
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE) ||
	    params[0].memref.size != sizeof(*context) ||
	    !params[0].memref.buffer) {
		FMSG("param types is not mathing %s\n", __func__);
		return res;
	}

	context = params[0].memref.buffer;
	op_handle = context->handle;

	aad = params[1].memref.buffer;
	aad_len = params[1].memref.size;

	TEE_AEUpdateAAD(op_handle, aad, aad_len);

	return TEE_SUCCESS;
}

TEE_Result aead_update(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = OUtput data
	 * params[3] = None
	 */

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE) ||
	    params[0].memref.size != sizeof(*context) ||
	    !params[0].memref.buffer)
		return res;

	context = params[0].memref.buffer;
	op_handle = context->handle;

	res = TEE_AEUpdate(op_handle, params[1].memref.buffer,
			   params[1].memref.size, params[2].memref.buffer,
			   &params[2].memref.size);

	FMSG("Return status of %s = 0x%x", __func__, res);

	return res;
}

TEE_Result aead_encrypt_final(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = Tag
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
	    params[0].memref.size != sizeof(*context) ||
	    !params[0].memref.buffer)
		return res;

	context = params[0].memref.buffer;
	op_handle = context->handle;

	res = TEE_AEEncryptFinal(op_handle, params[1].memref.buffer,
				 params[1].memref.size, params[2].memref.buffer,
				 &params[2].memref.size,
				 params[3].memref.buffer,
				 &params[3].memref.size);

	if (res == TEE_SUCCESS)
		TEE_FreeOperation(op_handle);

	FMSG("Return status of %s = 0x%x", __func__, res);

	return res;
}

TEE_Result aead_decrypt_final(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = Input data
	 * params[2] = Output data
	 * params[3] = Tag
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    params[0].memref.size != sizeof(*context) ||
	    !params[0].memref.buffer)
		return res;

	context = params[0].memref.buffer;
	op_handle = context->handle;

	res = TEE_AEDecryptFinal(op_handle, params[1].memref.buffer,
				 params[1].memref.size, params[2].memref.buffer,
				 &params[2].memref.size,
				 params[3].memref.buffer,
				 params[3].memref.size);

	if (res == TEE_SUCCESS)
		TEE_FreeOperation(op_handle);

	FMSG("Return status of %s = 0x%x", __func__, res);

	return res;
}
