// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "ta_rng.h"

#define BLOCK_SIZE BIT(12) // 4 KB

TEE_Result rng(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	unsigned int remaining_size;
	unsigned int block_size;
	unsigned char *buffer;
	unsigned char *block;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Random number buffer
	 */
	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
			    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	remaining_size = params[0].memref.size;
	buffer = params[0].memref.buffer;

	block_size = MIN(remaining_size, BLOCK_SIZE);

	block = TEE_Malloc(block_size, TEE_USER_MEM_HINT_NO_FILL_ZERO);
	if (!block)
		return TEE_ERROR_OUT_OF_MEMORY;

	while (remaining_size) {
		TEE_GenerateRandom(block, block_size);

		TEE_MemMove(buffer, block, block_size);

		remaining_size -= block_size;
		buffer += block_size;
		block_size = MIN(remaining_size, BLOCK_SIZE);
	}

	TEE_Free(block);

	return TEE_SUCCESS;
}
