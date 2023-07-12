// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2023 NXP
 */

#include <util.h>
#include <tee_internal_api.h>

#include "tee_subsystem.h"
#include "operation_context.h"

TEE_Result cancel_operation(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	uint32_t exp_param_types = 0;
	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Operation handle
	 * params[1] = None
	 * params[2] = None
	 * params[3] = None
	 */

	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types ||
	    params[0].memref.size != sizeof(struct shared_context))
		return res;

	context = params[0].memref.buffer;

	TEE_FreeOperation(context->handle);

	return TEE_SUCCESS;
}

TEE_Result copy_context(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationInfo src_info = { 0 };
	TEE_OperationHandle src_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle dst_handle = TEE_HANDLE_NULL;
	uint32_t exp_param_types = 0;
	struct shared_context *src_context;
	struct shared_context *dst_context;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Source operation handle
	 * params[1] = Destination operation handle
	 * params[2] = None
	 * params[3] = None
	 */

	exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_INOUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types ||
	    params[0].memref.size != sizeof(struct shared_context) ||
	    params[1].memref.size != sizeof(struct shared_context))
		return res;

	src_context = params[0].memref.buffer;
	src_handle = src_context->handle;

	TEE_GetOperationInfo(src_handle, &src_info);

	/*
	 * Allocate destination operation handle with same parameters as source
	 * operation handle
	 */
	res = TEE_AllocateOperation(&dst_handle, src_info.algorithm,
				    src_info.mode, src_info.maxKeySize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate operation (0x%x)", res);
		return res;
	}

	TEE_CopyOperation(dst_handle, src_handle);

	dst_context = params[1].memref.buffer;
	dst_context->handle = dst_handle;

	return TEE_SUCCESS;
}
