// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "common.h"

TEE_Result check_operation_keys_usage(TEE_OperationHandle op,
				      TEE_ObjectInfo *key_info,
				      uint32_t nb_keys)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationInfoMultiple *op_info = NULL;
	TEE_OperationInfoKey *op_key_info = NULL;
	uint32_t op_info_size;

	if (!key_info && nb_keys) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	op_info_size = sizeof(TEE_OperationInfoMultiple) +
		       nb_keys * sizeof(TEE_OperationInfoKey);

	op_info = TEE_Malloc(op_info_size, TEE_MALLOC_FILL_ZERO);
	if (!op_info) {
		EMSG("Allocation error");
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto end;
	}

	res = TEE_GetOperationInfoMultiple(op, op_info, &op_info_size);
	if (res) {
		EMSG("TEE_GetOperationInfoMultiple error 0x%x", res);
		goto end;
	}

	/* Check the number of keys expected */
	if (op_info->numberOfKeys != nb_keys) {
		EMSG("Operation expect %u keys but %u are given",
		     op_info->numberOfKeys, nb_keys);
		res = TEE_ERROR_BAD_PARAMETERS;
		goto end;
	}

	op_key_info = op_info->keyInformation;

	for (uint32_t i = 0; i < nb_keys; i++) {
		if (!(op_key_info[i].requiredKeyUsage &
		      key_info[i].objectUsage)) {
			EMSG("Bad key %u usage 0x%08x expected 0x%08x", i + 1,
			     op_key_info[i].requiredKeyUsage,
			     key_info[i].objectUsage);
			res = TEE_ERROR_BAD_PARAMETERS;
		}
	}

end:
	if (op_info)
		TEE_Free(op_info);

	return res;
}
