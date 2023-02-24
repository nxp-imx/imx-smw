// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "smw_status.h"

#include "global.h"
#include "debug.h"
#include "utils.h"
#include "list.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "exec.h"

static int smw_utils_execute_common(enum operation_id operation_id, void *args,
				    enum subsystem_id subsystem_id,
				    enum smw_op_step op_step, bool implicit)
{
	int status = SMW_STATUS_OK;

	struct subsystem_func *subsystem_func;
	const char *subsystem_name;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(INFO, "Execute Security Operation: %s (%d)\n",
		       smw_config_get_operation_name(operation_id),
		       operation_id);

	/*
	 * For implicit operation, no need to check subsystem capabilities.
	 * If subsytem enabled, the operation must be supported or returned
	 * not supported.
	 */
	if (!implicit) {
		status = smw_config_select_subsystem(operation_id, args,
						     &subsystem_id);
		if (status != SMW_STATUS_OK)
			return status;
	}

	/*
	 * For update and final no need to load subsystem.
	 * This is done at initialization
	 */
	if (op_step == SMW_OP_STEP_INIT || op_step == SMW_OP_STEP_ONESHOT) {
		status = smw_config_load_subsystem(subsystem_id);
		if (status != SMW_STATUS_OK)
			return status;
	}

	subsystem_name = smw_config_get_subsystem_name(subsystem_id);

	SMW_DBG_PRINTF(INFO, "Secure Subsystem: %s (%d)\n", subsystem_name,
		       subsystem_id);

	/* Register the latest Secure Subsystem selected */
	smw_utils_register_active_subsystem(subsystem_name);

	subsystem_func = smw_config_get_subsystem_func(subsystem_id);

	SMW_DBG_ASSERT(subsystem_func);
	SMW_DBG_ASSERT(subsystem_func->execute);

	status = subsystem_func->execute(operation_id, args);
	if (status != SMW_STATUS_OK)
		return status;

	/*
	 * Subsystem should not be unloaded at the end of initialization or
	 * update operation
	 */
	if (op_step == SMW_OP_STEP_FINAL || op_step == SMW_OP_STEP_ONESHOT)
		status = smw_config_unload_subsystem(subsystem_id);

	return status;
}

int smw_utils_execute_operation(enum operation_id operation_id, void *args,
				enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_ONESHOT, false);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_init(enum operation_id operation_id, void *args,
			   enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_INIT, false);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_update(enum operation_id operation_id, void *args,
			     enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_UPDATE, true);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_final(enum operation_id operation_id, void *args,
			    enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_FINAL, true);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_implicit(enum operation_id operation_id, void *args,
			       enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_ONESHOT, true);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
