// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2026 NXP
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

	if (subsystem == SMW_SUBSYSTEM_NAME_NONE)
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
