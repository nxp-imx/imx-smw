// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_status.h"
#include "smw_strings.h"

#include "psa/error.h"

#include "debug.h"
#include "subsystems.h"
#include "config.h"

#include "util_status.h"

psa_status_t call_smw_api(enum smw_status_code (*api)(void *a), void *args,
			  smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status;
	struct smw_config_psa_config config;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem_name || *subsystem_name)
		return PSA_ERROR_INVALID_ARGUMENT;

	smw_config_get_psa_config(&config);
	*subsystem_name = smw_config_get_subsystem_name(config.subsystem_id);

	status = api(args);
	if (config.alt && status == SMW_STATUS_OPERATION_NOT_SUPPORTED &&
	    *subsystem_name) {
		*subsystem_name = NULL;
		status = api(args);
	}

	return util_smw_to_psa_status(status);
}
