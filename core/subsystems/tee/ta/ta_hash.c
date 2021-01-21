// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <util.h>
#include <string.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "tee_subsystem.h"
#include "ta_hash.h"

#define ALGORITHM_ID(_algorithm_id)                                            \
	{                                                                      \
		.ca_id = TEE_ALGORITHM_ID_##_algorithm_id,                     \
		.ta_id = TEE_ALG_##_algorithm_id                               \
	}

/* Algorithm IDs must be ordered from lowest to highest. */
struct {
	enum tee_algorithm_id ca_id;
	uint32_t ta_id;
} algorithm_ids[] = { ALGORITHM_ID(MD5),    ALGORITHM_ID(SHA1),
		      ALGORITHM_ID(SHA224), ALGORITHM_ID(SHA256),
		      ALGORITHM_ID(SHA384), ALGORITHM_ID(SHA512),
		      ALGORITHM_ID(SM3) };

static TEE_Result get_algorithm_id(enum tee_algorithm_id ca_id, uint32_t *ta_id)
{
	unsigned int i;
	unsigned int size = ARRAY_SIZE(algorithm_ids);

	FMSG("Executing %s", __func__);

	if (!ta_id)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < size; i++) {
		if (algorithm_ids[i].ca_id < ca_id)
			continue;
		if (algorithm_ids[i].ca_id > ca_id)
			return TEE_ERROR_NOT_SUPPORTED;

		*ta_id = algorithm_ids[i].ta_id;
		break;
	}

	return TEE_SUCCESS;
}

TEE_Result hash(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm_id = 0;
	void *chunk;
	uint32_t chunkLen;
	void *hash;
	uint32_t hashLen;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Algorithm ID
	 * params[1] = Message
	 * params[2] = Digest
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_NONE))
		return res;

	/* Get TEE algorithm ID */
	res = get_algorithm_id(params[0].value.a, &algorithm_id);
	if (res) {
		EMSG("Failed to get algorithm ID: 0x%x", res);
		return res;
	}

	chunk = params[1].memref.buffer;
	chunkLen = params[1].memref.size;
	hash = params[2].memref.buffer;
	hashLen = params[2].memref.size;

	res = TEE_AllocateOperation(&operation, algorithm_id, TEE_MODE_DIGEST,
				    0);
	if (res) {
		EMSG("Failed to alloc operation: 0x%x", res);
		return res;
	}

	/* Compute digest */
	res = TEE_DigestDoFinal(operation, chunk, chunkLen, hash, &hashLen);
	if (res) {
		EMSG("Failed to compute hash: 0x%x", res);
		goto exit;
	}

	/* Update the hash length */
	params[2].memref.size = hashLen;

exit:
	TEE_FreeOperation(operation);

	return res;
}
