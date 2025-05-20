// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "smw_status.h"

#include "debug.h"
#include "exec.h"
#include "object_query.h"
#include "subsystems.h"

int util_object_query_subsystem(struct smw_object_query *query,
				enum operation_id *op_ids, unsigned int nb_ops)
{
	int status = SMW_STATUS_OK;

	enum subsystem_id subsystem_id = 0;
	enum subsystem_id max_subsystem_id = SUBSYSTEM_ID_NB;
	enum operation_id op_obj_present = OPERATION_ID_IS_OBJECT_PRESENT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!query || !query->key) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	subsystem_id = query->subsystem_id;

	/*
	 * If the subsystem is not specified, try to get data information
	 * querying each subsystem supporting either store or retrieve data.
	 */
	if (subsystem_id == SUBSYSTEM_ID_INVALID) {
		subsystem_id = 0;
	} else if (subsystem_id < SUBSYSTEM_ID_NB) {
		max_subsystem_id = subsystem_id + 1;
	} else {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	for (; subsystem_id < max_subsystem_id; subsystem_id++) {
		status = smw_config_is_operations_supported(op_ids, nb_ops,
							    subsystem_id);
		if (status == SMW_STATUS_OPERATION_NOT_SUPPORTED ||
		    status == SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED) {
			status = SMW_STATUS_UNKNOWN_ID;
			continue;
		}

		status = smw_utils_execute_implicit(op_obj_present, query,
						    subsystem_id);
		if (status != SMW_STATUS_UNKNOWN_ID)
			break;
	}

	if (status == SMW_STATUS_OK)
		query->subsystem_id = subsystem_id;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
