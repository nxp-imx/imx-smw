// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2024 NXP
 */

#include <util.h>
#include <string.h>
#include <utee_defines.h>
#include <tee_internal_api.h>

#include "tee_subsystem.h"
#include "hash.h"

#define ALGORITHM_INFO(_algo)                                                  \
	{                                                                      \
		.ca_id = TEE_ALGORITHM_ID_##_algo, .ta_id = TEE_ALG_##_algo,   \
		.length = TEE_##_algo##_HASH_SIZE                              \
	}

/* Algorithm IDs must be ordered from lowest to highest. */
static const struct algorithm_info {
	enum tee_algorithm_id ca_id;
	uint32_t ta_id;
	size_t length;
} algorithm_infos[] = { ALGORITHM_INFO(MD5),	  ALGORITHM_INFO(SHA1),
			ALGORITHM_INFO(SHA224),	  ALGORITHM_INFO(SHA256),
			ALGORITHM_INFO(SHA384),	  ALGORITHM_INFO(SHA512),
			ALGORITHM_INFO(SHA3_224), ALGORITHM_INFO(SHA3_256),
			ALGORITHM_INFO(SHA3_384), ALGORITHM_INFO(SHA3_512),
			ALGORITHM_INFO(SM3) };

static TEE_Result get_algorithm_info(enum tee_algorithm_id ca_id,
				     const struct algorithm_info **info)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(algorithm_infos);

	FMSG("Executing %s", __func__);

	if (!info)
		return TEE_ERROR_BAD_PARAMETERS;

	for (; i < size; i++) {
		if (algorithm_infos[i].ca_id < ca_id)
			continue;
		if (algorithm_infos[i].ca_id > ca_id)
			return TEE_ERROR_NOT_SUPPORTED;

		*info = &algorithm_infos[i];
		break;
	}

	return TEE_SUCCESS;
}

TEE_Result ta_get_digest_length(enum tee_algorithm_id tee_algorithm_id,
				size_t *digest_len)
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
	const struct algorithm_info *info = NULL;

	FMSG("Executing %s", __func__);

	if (digest_len) {
		res = get_algorithm_info(tee_algorithm_id, &info);
		if (!info)
			res = TEE_ERROR_BAD_PARAMETERS;
		if (res == TEE_SUCCESS)
			*digest_len = info->length;
	}

	return res;
}

TEE_Result ta_get_hash_ca_id(size_t digest_len, enum tee_algorithm_id *ca_id)
{
	unsigned int i = 0;
	unsigned int size = ARRAY_SIZE(algorithm_infos);

	FMSG("Executing %s", __func__);

	if (ca_id) {
		for (; i < size; i++) {
			if (algorithm_infos[i].length < digest_len)
				continue;
			if (algorithm_infos[i].length > digest_len)
				return TEE_ERROR_NOT_SUPPORTED;

			*ca_id = algorithm_infos[i].ca_id;
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result ta_compute_digest(enum tee_algorithm_id tee_algorithm_id,
			     const void *chunk, size_t chunk_len, void *hash,
			     size_t *hash_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	const struct algorithm_info *algorithm_info = NULL;

	FMSG("Executing %s", __func__);

	if (!hash_len)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Get TEE algorithm ID */
	res = get_algorithm_info(tee_algorithm_id, &algorithm_info);
	if (res != TEE_SUCCESS || !algorithm_info) {
		EMSG("Failed to get algorithm info: 0x%x", res);
		return res;
	}

	if (!hash) {
		*hash_len = algorithm_info->length;
		return TEE_SUCCESS;
	}

	res = TEE_AllocateOperation(&operation, algorithm_info->ta_id,
				    TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to alloc operation: 0x%x", res);
		return res;
	}

	/* Compute digest */
	res = TEE_DigestDoFinal(operation, chunk, chunk_len, hash, hash_len);
	if (res != TEE_SUCCESS)
		EMSG("Failed to compute digest: 0x%x", res);

	TEE_FreeOperation(operation);

	return res;
}

TEE_Result hash(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	int tee_algorithm_id = TEE_ALGORITHM_ID_INVALID;

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

	if (ADD_OVERFLOW(params[0].value.a, 0, &tee_algorithm_id))
		return res;

	res = ta_compute_digest(tee_algorithm_id, params[1].memref.buffer,
				params[1].memref.size, params[2].memref.buffer,
				&params[2].memref.size);

	return res;
}

TEE_Result hash_init(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	int tee_algorithm_id = TEE_ALGORITHM_ID_INVALID;
	const struct algorithm_info *algorithm_info = NULL;
	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[0] = Algorithm ID
	 * params[1] = Message
	 * params[3] = Shared context
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
	    !params[1].memref.buffer != !params[1].memref.size ||
	    params[3].memref.size != sizeof(*context) ||
	    !params[3].memref.buffer)
		return res;

	if (ADD_OVERFLOW(params[0].value.a, 0, &tee_algorithm_id))
		return res;

	/* Get TEE algorithm ID */
	res = get_algorithm_info(tee_algorithm_id, &algorithm_info);
	if (res != TEE_SUCCESS || !algorithm_info) {
		EMSG("!Failed to get algorithm info: 0x%x", res);
		return res;
	}

	res = TEE_AllocateOperation(&operation, algorithm_info->ta_id,
				    TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to alloc operation: 0x%x", res);
		return res;
	}

	/* Compute digest */
	if (params[1].memref.buffer && params[1].memref.size)
		TEE_DigestUpdate(operation, params[1].memref.buffer,
				 params[1].memref.size);

	/* Share operation handle */
	context = params[3].memref.buffer;
	context->handle = operation;

	return res;
}

TEE_Result hash_update(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[1] = Message
	 * params[3] = Shared context
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    !params[1].memref.buffer != !params[1].memref.size ||
	    params[3].memref.size != sizeof(*context) ||
	    !params[3].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;

	context = params[3].memref.buffer;

	/* Compute digest */
	TEE_DigestUpdate(context->handle, params[1].memref.buffer,
			 params[1].memref.size);

	return TEE_SUCCESS;
}

TEE_Result hash_final(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_BAD_PARAMETERS;

	struct shared_context *context = NULL;

	FMSG("Executing %s", __func__);

	/*
	 * params[1] = Message
	 * params[2] = Digest
	 * params[3] = Shared context
	 */
	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_MEMREF_INPUT,
					   TEE_PARAM_TYPE_MEMREF_OUTPUT,
					   TEE_PARAM_TYPE_MEMREF_INPUT) ||
	    !params[1].memref.buffer != !params[1].memref.size ||
	    params[3].memref.size != sizeof(*context) ||
	    !params[3].memref.buffer)
		return res;

	context = params[3].memref.buffer;

	res = TEE_DigestDoFinal(context->handle, params[1].memref.buffer,
				params[1].memref.size, params[2].memref.buffer,
				&params[2].memref.size);
	if (res != TEE_SUCCESS)
		EMSG("Failed to compute digest: 0x%x", res);

	return res;
}
