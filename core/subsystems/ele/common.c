// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "config.h"
#include "debug.h"
#include "utils.h"

#include "common.h"

#define HASH_ALGO(_id, _hsm_id, _length)                                       \
	{                                                                      \
		.algo_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                      \
		.ele_algo = HSM_HASH_ALGO_##_hsm_id, .length = _length         \
	}

static const struct ele_hash_algo hash_algos[] = {
	HASH_ALGO(SHA224, SHA_224, 28), HASH_ALGO(SHA256, SHA_256, 32),
	HASH_ALGO(SHA384, SHA_384, 48), HASH_ALGO(SHA512, SHA_512, 64)
};

const struct ele_hash_algo *
ele_get_hash_algo(enum smw_config_hash_algo_id algo_id)
{
	const struct ele_hash_algo *hash_algo = NULL;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(hash_algos); i++) {
		if (hash_algos[i].algo_id == algo_id) {
			hash_algo = &hash_algos[i];
			break;
		}
	}

	return hash_algo;
}
