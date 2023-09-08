// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <tee_client_api.h>

#include "smw_status.h"

#include "config.h"
#include "debug.h"

#include "tee.h"

#define ALGORITHM_ID(_id)                                                      \
	{                                                                      \
		.smw_id = SMW_CONFIG_HASH_ALGO_ID_##_id,                       \
		.tee_id = TEE_ALGORITHM_ID_##_id                               \
	}

/**
 * struct - Hash algorithm IDs
 * @smw_id: Hash algorithm ID as defined in SMW.
 * @tee_id: Hash algorithm ID as defined in TEE subsystem.
 */
static const struct {
	enum smw_config_hash_algo_id smw_id;
	enum tee_algorithm_id tee_id;
} algorithm_ids[] = { ALGORITHM_ID(MD5),    ALGORITHM_ID(SHA1),
		      ALGORITHM_ID(SHA224), ALGORITHM_ID(SHA256),
		      ALGORITHM_ID(SHA384), ALGORITHM_ID(SHA512),
		      ALGORITHM_ID(SM3),    ALGORITHM_ID(INVALID) };

int tee_convert_hash_algorithm_id(enum smw_config_hash_algo_id smw_id,
				  enum tee_algorithm_id *tee_id)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	unsigned int i = 0;
	unsigned int array_size = ARRAY_SIZE(algorithm_ids);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < array_size; i++) {
		if (algorithm_ids[i].smw_id == smw_id) {
			*tee_id = algorithm_ids[i].tee_id;
			status = SMW_STATUS_OK;
			break;
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
