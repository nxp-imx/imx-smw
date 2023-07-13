// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "smw_status.h"
#include "smw_strings.h"

#include "psa/error.h"

#include "debug.h"
#include "subsystems.h"
#include "config.h"

#include "util_status.h"

smw_subsystem_t get_psa_default_subsystem(void)
{
	smw_subsystem_t subsystem_name = NULL;

	struct smw_config_psa_config config = { 0 };

	smw_config_get_psa_config(&config);

	if (config.subsystem_id != SUBSYSTEM_ID_INVALID)
		subsystem_name =
			smw_config_get_subsystem_name(config.subsystem_id);

	return subsystem_name;
}

psa_status_t call_smw_api(enum smw_status_code (*api)(void *a), void *args,
			  smw_subsystem_t *subsystem_name)
{
	enum smw_status_code status = SMW_STATUS_INVALID_PARAM;
	struct smw_config_psa_config config = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!subsystem_name || *subsystem_name)
		goto end;

	smw_config_get_psa_config(&config);

	if (config.subsystem_id == SUBSYSTEM_ID_INVALID)
		*subsystem_name = NULL;
	else
		*subsystem_name =
			smw_config_get_subsystem_name(config.subsystem_id);

	status = api(args);
	if (config.alt && status == SMW_STATUS_OPERATION_NOT_SUPPORTED &&
	    *subsystem_name) {
		*subsystem_name = NULL;
		status = api(args);
	}

end:
	return util_smw_to_psa_status(status);
}
