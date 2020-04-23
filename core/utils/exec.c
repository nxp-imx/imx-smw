// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"

int smw_utils_execute_operation(enum operation_id operation_id, void *args,
				enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_OK;

	void *params = NULL;
	struct operation_func *operation_func;
	struct subsystem_func *subsystem_func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(INFO, "Execute Security Operation: %s (%d)\n",
		       smw_config_get_operation_name(operation_id),
		       operation_id);

	operation_func = smw_config_get_operation_func(operation_id);

	SMW_DBG_ASSERT(operation_func);
	SMW_DBG_ASSERT(operation_func->check_subsystem_caps);

	status = smw_config_get_subsystem_caps(&subsystem_id, operation_id,
					       &params);
	if (status != SMW_STATUS_OK)
		goto end;

	status = operation_func->check_subsystem_caps(args, params);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_load_subsystem(subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(INFO, "Secure Subsystem: %s (%d)\n",
		       smw_config_get_subsystem_name(subsystem_id),
		       subsystem_id);

	subsystem_func = smw_config_get_subsystem_func(subsystem_id);

	SMW_DBG_ASSERT(subsystem_func);
	SMW_DBG_ASSERT(subsystem_func->execute);

	status = subsystem_func->execute(operation_id, args);
	if (status != SMW_STATUS_OK)
		goto end;

	status = smw_config_unload_subsystem(subsystem_id);

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
