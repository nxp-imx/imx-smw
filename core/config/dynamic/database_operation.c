// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"

#include "osal.h"
#include "compiler.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "name.h"
#include "operations.h"
#include "subsystems.h"

#include "database.h"

#include "operations_apis.h"

int get_operation_id(const char *string, enum operation_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_get_string_index(string, operation_strings,
					    OPERATION_ID_NB, id);
	if (status == SMW_STATUS_UNKNOWN_NAME)
		status = SMW_STATUS_UNKNOWN_CONFIG_OP_NAME;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_select_subsystem(enum operation_id operation_id, void *args,
				enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	int status_mutex = SMW_STATUS_OK;
	struct operation_func *operation_func = NULL;
	int (*check_subsystem_caps)(void *args, void *node) = NULL;

	struct node *node = NULL;
	unsigned int ref_id = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(subsystem_id);

	operation_func = get_operation_func(operation_id);
	SMW_DBG_ASSERT(operation_func);

	check_subsystem_caps = operation_func->check_subsystem_caps;
	SMW_DBG_ASSERT(check_subsystem_caps);

	ref_id = *subsystem_id;

	status_mutex = config_db_mutex_lock();
	if (status_mutex != SMW_STATUS_OK)
		goto end;

	status = find_subsystem_per_operation(operation_id, ref_id, &node);
	if (status != SMW_STATUS_OK)
		goto end;

	if (ref_id != SUBSYSTEM_ID_INVALID) {
		status = check_subsystem_caps(args, node);
		goto end;
	}

	while (node) {
		status = check_subsystem_caps(args, node);

		if (status == SMW_STATUS_OK) {
			ref_id = smw_utils_list_get_ref(node);
			if (ref_id < SUBSYSTEM_ID_NB)
				*subsystem_id = ref_id;
			break;
		}

		status = find_subsystem_per_operation(operation_id, ref_id,
						      &node);
		if (status != SMW_STATUS_OK)
			break;
	}

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
	int status = SMW_STATUS_OK;

	struct database *database = NULL;
	struct operation_func *operation_func = NULL;
	unsigned int index = operation_id;

	struct smw_utils_list *list = NULL;
	struct node *node = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	database = get_database();

	if (!database)
		return SMW_STATUS_INVALID_CONFIG_DATABASE;

	SMW_DBG_ASSERT(params);
	OPERATION_ID_ASSERT(operation_id);

	if (ref)
		SUBSYSTEM_ID_ASSERT(*ref);

	SMW_DBG_PRINTF(DEBUG, "Security operation id: %d\n", operation_id);
	SMW_DBG_PRINTF(DEBUG, "Secure subsystem is: %s\n",
		       ref ? smw_config_get_subsystem_string(*ref) : "Unknown");

	operation_func = get_operation_func(operation_id);

	list = &database->operation[index].subsystems_list;

	status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	node = smw_utils_list_find_first(list, ref);
	if (node)
		status = SMW_STATUS_OK;

	while (node) {
		operation_func->merge(params, smw_utils_list_get_data(node));

		node = smw_utils_list_find_next(node, ref);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

struct operation_func *get_operation_func(enum operation_id id)
{
	unsigned int index;

	SMW_DBG_TRACE_FUNCTION_CALL;

	OPERATION_ID_ASSERT(id);

	index = id;
	return operation_func[index]();
}

smw_operation_t smw_config_get_operation_name(enum operation_id id)
{
	unsigned int index;

	OPERATION_ID_ASSERT(id);

	index = id;
	return operation_names[index];
}
