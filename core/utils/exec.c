// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "exec.h"

static int smw_utils_execute_common(enum operation_id operation_id, void *args,
				    enum subsystem_id subsystem_id,
				    enum smw_op_step op_step)
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
		return status;

	/*
	 * For update and final operation no need to check subsystem
	 * capabilities and load subsystem. This is done at initialization
	 */
	if (op_step == SMW_OP_STEP_INIT || op_step == SMW_OP_STEP_ONESHOT) {
		status = operation_func->check_subsystem_caps(args, params);
		if (status != SMW_STATUS_OK)
			return status;

		status = smw_config_load_subsystem(subsystem_id);
		if (status != SMW_STATUS_OK)
			return status;
	}

	SMW_DBG_PRINTF(INFO, "Secure Subsystem: %s (%d)\n",
		       smw_config_get_subsystem_name(subsystem_id),
		       subsystem_id);

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
					  SMW_OP_STEP_ONESHOT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_init(enum operation_id operation_id, void *args,
			   enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_INIT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_update(enum operation_id operation_id, void *args,
			     enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_UPDATE);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_final(enum operation_id operation_id, void *args,
			    enum subsystem_id subsystem_id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_execute_common(operation_id, args, subsystem_id,
					  SMW_OP_STEP_FINAL);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
