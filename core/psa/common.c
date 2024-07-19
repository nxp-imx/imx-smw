// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include "smw/names.h"
#include "smw_status.h"

#include "psa/error.h"

#include "debug.h"
#include "subsystems.h"
#include "config.h"

#include "util_status.h"

smw_subsystem_t get_psa_default_subsystem(void)
{
	struct smw_config_psa_config config = { 0 };

	smw_config_get_psa_config(&config);

	return config.subsystem_name;
}

psa_status_t call_smw_api(enum smw_status_code (*api)(void *a), void *args,
			  smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_config_psa_config config = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem_name || (*subsystem_name >= SMW_SUBSYSTEM_NAME_NB))
		goto end;

	smw_config_get_psa_config(&config);

	*subsystem_name = config.subsystem_name;

	status = api(args);
	if (config.alt && status == SMW_STATUS_OPERATION_NOT_SUPPORTED &&
	    *subsystem_name) {
		*subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
		status = api(args);
	}

end:
	return util_smw_to_psa_status(status);
}
