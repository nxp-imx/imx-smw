// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_status.h"
#include "smw_strings.h"

#include "debug.h"
#include "subsystems.h"
#include "config.h"

enum smw_status_code call_smw_api(enum smw_status_code (*api)(void *a),
				  void *args,
				  struct smw_config_psa_config *config,
				  smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = api(args);
	if (config->alt && status == SMW_STATUS_OPERATION_NOT_SUPPORTED &&
	    subsystem_name && *subsystem_name) {
		*subsystem_name = NULL;
		status = api(args);
	}

	return status;
}

smw_subsystem_t get_subsystem_name(struct smw_config_psa_config *config)
{
	if (config->subsystem_id != SUBSYSTEM_ID_INVALID)
		return smw_config_get_subsystem_name(config->subsystem_id);

	return NULL;
}
