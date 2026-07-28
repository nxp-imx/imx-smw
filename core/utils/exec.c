// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2024, 2026 NXP
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
				    enum smw_op_step op_step,
				    enum smw_op_implicit op_implicit)
{
	int status = SMW_STATUS_OK;

	struct subsystem_func *subsystem_func = NULL;
	smw_subsystem_t subsystem_name = SMW_SUBSYSTEM_NAME_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(INFO, "Execute Security Operation: %d (%d)\n",
		       smw_config_get_operation_name(operation_id),
		       operation_id);

	/*
	 * Select the subsystem to execute the operation. For non-implicit
	 * operations the subsystem capabilities are verified against @args.
	 * For implicit operations the is_operation_supported() hook on the
	 * subsystem is used instead, so that the correct subsystem is found
	 * even when subsystem_id is SUBSYSTEM_ID_INVALID.
	 * For multipart update/final (OP_INHERIT_IMPLICIT) the subsystem is
	 * already known from initialization; skip support checks entirely.
	 */
	status = smw_config_select_subsystem(operation_id, args, &subsystem_id,
					     op_implicit);
	if (status != SMW_STATUS_OK) {
		if ((status == SMW_STATUS_OPERATION_NOT_CONFIGURED ||
		     status == SMW_STATUS_OPERATION_NOT_SUPPORTED) &&
		    subsystem_id < SUBSYSTEM_ID_NB) {
			/*
			 * A subsystem is selected but the operation is
			 * either not configured or not supported.
			 * Register the subsystem as active to allow application
			 * to get the subsystem returning operation not
			 * configured or supported.
			 */
			subsystem_name =
				smw_config_get_subsystem_name(subsystem_id);

			SMW_DBG_PRINTF(INFO, "%s Select Secure Subsystem: %d\n",
				       __func__, subsystem_name);

			/* Register the latest Secure Subsystem selected */
			smw_utils_register_active_subsystem(subsystem_name);
		}

		return status;
	}

	if (subsystem_id >= SUBSYSTEM_ID_NB)
		return SMW_STATUS_INVALID_PARAM;

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

	SMW_DBG_PRINTF(INFO, "%s Execute on Secure Subsystem: %d (%d)\n",
		       __func__, subsystem_name, subsystem_id);

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
	SMW_DBG_TRACE_FUNCTION_CALL;

	int status = smw_utils_execute_common(operation_id, args, subsystem_id,
					      SMW_OP_STEP_ONESHOT,
					      SMW_OP_NOT_IMPLICIT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_init(enum operation_id operation_id, void *args,
			   enum subsystem_id subsystem_id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	int status =
		smw_utils_execute_common(operation_id, args, subsystem_id,
					 SMW_OP_STEP_INIT, SMW_OP_NOT_IMPLICIT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_update(enum operation_id operation_id, void *args,
			     enum subsystem_id subsystem_id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	int status = smw_utils_execute_common(operation_id, args, subsystem_id,
					      SMW_OP_STEP_UPDATE,
					      SMW_OP_INHERIT_IMPLICIT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_final(enum operation_id operation_id, void *args,
			    enum subsystem_id subsystem_id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	int status = smw_utils_execute_common(operation_id, args, subsystem_id,
					      SMW_OP_STEP_FINAL,
					      SMW_OP_INHERIT_IMPLICIT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_execute_implicit(enum operation_id operation_id, void *args,
			       enum subsystem_id subsystem_id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	int status = smw_utils_execute_common(operation_id, args, subsystem_id,
					      SMW_OP_STEP_ONESHOT,
					      SMW_OP_REAL_IMPLICIT);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
