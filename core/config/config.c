// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <stdbool.h>

#include "smw_config.h"
#include "smw_status.h"

#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

#include "common.h"

__export enum smw_status_code
smw_config_subsystem_present(smw_subsystem_t subsystem)
{
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem)
		return SMW_STATUS_INVALID_PARAM;

	return smw_config_get_subsystem_id(subsystem, &id);
}

__export enum smw_status_code
smw_config_subsystem_loaded(smw_subsystem_t subsystem)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status == SMW_STATUS_OK) {
		if (!get_smw_ctx())
			status = SMW_STATUS_INVALID_LIBRARY_CONTEXT;
		else if (get_subsystem_state(id) == SUBSYSTEM_STATE_LOADED)
			status = SMW_STATUS_SUBSYSTEM_LOADED;
		else
			status = SMW_STATUS_SUBSYSTEM_NOT_LOADED;
	}

	return status;
}

__export __weak enum smw_status_code
smw_config_check_digest(smw_subsystem_t subsystem, smw_hash_algo_t algo)
{
	(void)subsystem;
	(void)algo;

	return SMW_STATUS_OPERATION_NOT_CONFIGURED;
}

__export enum smw_status_code
smw_config_check_generate_key(smw_subsystem_t subsystem,
			      struct smw_key_info *info)
{
	int status = SMW_STATUS_INVALID_PARAM;
	enum subsystem_id id = SUBSYSTEM_ID_INVALID;
	enum smw_config_key_type_id key_type_id =
		SMW_CONFIG_KEY_TYPE_ID_INVALID;
	struct key_operation_params params = { 0 };
	struct range *key_size_range = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!info || !info->key_type_name)
		return status;

	status = smw_config_get_subsystem_id(subsystem, &id);
	if (status != SMW_STATUS_OK)
		return status;

	status = smw_config_get_key_type_id(info->key_type_name, &key_type_id);
	if (status != SMW_STATUS_OK)
		return status;

	status = get_operation_params(OPERATION_ID_GENERATE_KEY, id, &params);
	if (status != SMW_STATUS_OK)
		return status;

	if (!check_id(key_type_id, params.key.type_bitmap))
		return SMW_STATUS_OPERATION_NOT_CONFIGURED;

	key_size_range = &params.key.size_range[key_type_id];
	if (info->security_size) {
		if (!check_size(info->security_size, key_size_range))
			return SMW_STATUS_OPERATION_NOT_CONFIGURED;
	} else {
		info->security_size_min = key_size_range->min;
		info->security_size_max = key_size_range->max;
	}

	return SMW_STATUS_OK;
}

__export __weak enum smw_status_code
smw_config_check_cipher(smw_subsystem_t subsystem, struct smw_cipher_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_sign(smw_subsystem_t subsystem,
		      struct smw_signature_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__export __weak enum smw_status_code
smw_config_check_verify(smw_subsystem_t subsystem,
			struct smw_signature_info *info)
{
	(void)subsystem;
	(void)info;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
