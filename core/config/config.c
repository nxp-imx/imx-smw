// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdbool.h>

#include "smw_config.h"
#include "smw_status.h"

#include "compiler.h"
#include "operations.h"
#include "subsystems.h"
#include "common.h"
#include "config.h"

__export int smw_config_subsystem_present(const char *subsystem)
{
	unsigned int id;

	if (!subsystem)
		return SMW_STATUS_INVALID_PARAM;

	return smw_config_get_subsystem_id(subsystem, &id);
}

__export int smw_config_subsystem_check_digest(const char *subsystem,
					       const char *algo)
{
	int status;
	unsigned int id;
	unsigned int algo_id;
	struct hash_params *params;

	if (!subsystem || !algo)
		return SMW_STATUS_INVALID_PARAM;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_hash_algo_id(algo, &algo_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_subsystem_caps(&id, OPERATION_ID_HASH,
					       (void **)&params);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(algo_id, params->algo_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	return SMW_STATUS_OK;
}
