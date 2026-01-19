// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2026 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"

#include "config.h"
#include "debug.h"

#include "tee.h"

#define HASH_ALGO(_id, _length)                                                \
	{                                                                      \
		.smw_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                       \
		.tee_id = TEE_ALGORITHM_ID_##_id, .length = _length            \
	}

static const struct tee_hash_algo hash_algos[] = {
	HASH_ALGO(MD5, 16),	 HASH_ALGO(SHA1, 20),
	HASH_ALGO(SHA224, 28),	 HASH_ALGO(SHA256, 32),
	HASH_ALGO(SHA384, 48),	 HASH_ALGO(SHA512, 64),
	HASH_ALGO(SHA3_224, 28), HASH_ALGO(SHA3_256, 32),
	HASH_ALGO(SHA3_384, 48), HASH_ALGO(SHA3_512, 64),
	HASH_ALGO(SM3, 32),	 HASH_ALGO(SHAKE256, 64),
	HASH_ALGO(INVALID, 0)
};

const struct tee_hash_algo *
tee_get_hash_algo(enum smw_config_hash_algo_id smw_id)
{
	const struct tee_hash_algo *hash_algo = NULL;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algos[i].smw_id == smw_id) {
			hash_algo = &hash_algos[i];
			break;
		}
	}

	return hash_algo;
}

int tee_convert_hash_algorithm_id(enum smw_config_hash_algo_id smw_id,
				  enum tee_algorithm_id *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	const struct tee_hash_algo *hash_algo = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	hash_algo = tee_get_hash_algo(smw_id);
	if (!hash_algo)
		goto end;

	*tee_id = hash_algo->tee_id;

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int set_tmpref_buffer(unsigned int mem_type, unsigned int param_idx,
		      unsigned char *buffer, unsigned int buffer_len,
		      TEEC_Operation *op)
{
	if (param_idx > (TEE_NUM_PARAMS - 1))
		return SMW_STATUS_INVALID_PARAM;

	SET_TEEC_PARAMS_TYPE(op->paramTypes, mem_type, param_idx);
	op->params[param_idx].tmpref.buffer = buffer;
	op->params[param_idx].tmpref.size = buffer_len;

	return SMW_STATUS_OK;
}
