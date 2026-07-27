// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stddef.h>

#include "smw_status.h"

#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "debug.h"

#include "database.h"

int smw_config_select_subsystem(enum operation_id operation_id, void *args,
				enum subsystem_id *subsystem_id,
				enum smw_op_implicit op_implicit)
{
	(void)args;

	int status = SMW_STATUS_OK;
	int status_mutex = SMW_STATUS_OK;

	struct node *node = NULL;
	unsigned int ref_id = 0;

	SMW_DBG_ASSERT(subsystem_id);

	ref_id = *subsystem_id;

	if (op_implicit == SMW_OP_INHERIT_IMPLICIT) {
		/* Subsystem already known from init; no check needed. */
		return SMW_STATUS_OK;
	} else if (op_implicit == SMW_OP_REAL_IMPLICIT) {
		status = select_subsystem_implicit_op(operation_id, &ref_id);
	} else {
		status_mutex = config_db_mutex_lock();
		if (status_mutex != SMW_STATUS_OK)
			goto end;

		status = find_subsystem_per_operation(operation_id, ref_id,
						      &node);
		if (status != SMW_STATUS_OK)
			goto end;

		ref_id = smw_utils_list_get_ref(node);
	}

	if (ref_id < SUBSYSTEM_ID_NB)
		*subsystem_id = ref_id;

end:
	if (status_mutex == SMW_STATUS_OK) {
		status_mutex = config_db_mutex_unlock();
		if (status == SMW_STATUS_OK)
			status = status_mutex;
	}

	return status;
}

int get_operation_params(enum operation_id operation_id, unsigned int *ref,
			 void *params)
{
	(void)operation_id;
	(void)ref;
	(void)params;

	return SMW_STATUS_OK;
}

smw_operation_t smw_config_get_operation_name(enum operation_id id)
{
	(void)id;

	return SMW_OPERATION_NAME_NONE;
}
