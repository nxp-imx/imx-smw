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
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;

	if (!subsystem)
		return SMW_STATUS_INVALID_PARAM;

	return smw_config_get_subsystem_id(subsystem, &id);
}

__export int smw_config_check_digest(const char *subsystem, const char *algo)
{
	int status;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_hash_algo_id algo_id;
	struct hash_params *params;

	if (!algo)
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

__export int smw_config_check_generate_key(const char *subsystem,
					   struct smw_key_info *info)
{
	int status;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id keytype_id;
	struct key_operation_params *params;

	if (!info || !info->key_type_name)
		return SMW_STATUS_INVALID_PARAM;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(info->key_type_name, &keytype_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_subsystem_caps(&id, OPERATION_ID_GENERATE_KEY,
					       (void **)&params);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(keytype_id, params->key_type_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	if (info->security_size) {
		if (!check_security_size(info->security_size,
					 params->key_size_min,
					 params->key_size_max))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	} else {
		info->security_size_min = params->key_size_min;
		info->security_size_max = params->key_size_max;
	}

	return SMW_STATUS_OK;
}
