// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "list.h"
#include "name.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"
#include "database.h"

#include "subsystems_apis.h"
#include "operations_apis.h"

#define SUBSYSTEM_ID_ASSERT(id)                                                \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < SUBSYSTEM_ID_NB) &&                      \
			       (_id != SUBSYSTEM_ID_INVALID));                 \
	} while (0)

#define OPERATION_ID_ASSERT(id)                                                \
	do {                                                                   \
		typeof(id) _id = (id);                                         \
		SMW_DBG_ASSERT((_id < OPERATION_ID_NB) &&                      \
			       (_id != OPERATION_ID_INVALID));                 \
	} while (0)

struct database database;

static const char *const load_method_names[] = {
	[LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD] = "AT_CONFIG_LOAD_UNLOAD",
	[LOAD_METHOD_ID_AT_FIRST_CALL_LOAD] = "AT_FIRST_CALL_LOAD",
	[LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION] =
		"AT_CONTEXT_CREATION_DESTRUCTION"
};

static void init_subsystem(struct subsystem *subsystem, bool reset)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	subsystem->configured = false;
	subsystem->state = SUBSYSTEM_STATE_UNLOADED;
	subsystem->load_method_id = LOAD_METHOD_ID_DEFAULT;
	subsystem->operations_bitmap = 0;
	if (reset)
		smw_utils_list_destroy(&subsystem->operations_caps_list);
	else
		smw_utils_list_init(&subsystem->operations_caps_list);
	smw_utils_list_print(&subsystem->operations_caps_list);
}

void init_database(bool reset)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++)
		init_subsystem(&database.subsystem[i], reset);

	for (i = 0; i < OPERATION_ID_NB; i++)
		database.operation[i] = SUBSYSTEM_ID_INVALID;
}

void set_bit(unsigned long *bitmap, unsigned int size, unsigned int offset)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(offset < size);
	*bitmap |= (1 << offset);
}

static bool get_bit(unsigned long bitmap, unsigned int size,
		    unsigned int offset)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(offset < size);
	return (bitmap & (1 << offset)) ? true : false;
}

void set_subsystem_configured(enum subsystem_id id)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	database.subsystem[index].configured = true;
}

static bool is_subsystem_configured(enum subsystem_id id)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	return database.subsystem[index].configured;
}

static void set_subsystem_state(enum subsystem_id id,
				enum subsystem_state state)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);
	SMW_DBG_ASSERT(state != database.subsystem[index].state);

	database.subsystem[index].state = state;
}

static enum subsystem_state get_subsystem_state(enum subsystem_id id)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	return database.subsystem[index].state;
}

void set_subsystem_load_method(enum subsystem_id id,
			       enum load_method_id load_method_id)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	database.subsystem[index].load_method_id = load_method_id;
}

static enum load_method_id get_subsystem_load_method_id(enum subsystem_id id)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	return database.subsystem[index].load_method_id;
}

void set_subsystem_operation_bitmap(enum subsystem_id subsystem_id,
				    enum operation_id operation_id)
{
	unsigned int index = subsystem_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(subsystem_id);
	OPERATION_ID_ASSERT(operation_id);

	set_bit(&database.subsystem[index].operations_bitmap,
		sizeof(database.subsystem[index].operations_bitmap) << 3,
		operation_id);
}

void set_subsystem_default(enum operation_id operation_id,
			   enum subsystem_id subsystem_id, bool is_default)
{
	unsigned int index = operation_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(subsystem_id);
	OPERATION_ID_ASSERT(operation_id);

	if (is_default || database.operation[index] == SUBSYSTEM_ID_INVALID)
		database.operation[index] = subsystem_id;
}

void smw_config_notify_subsystem_failure(enum subsystem_id id)
{
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	smw_utils_mutex_lock(ctx.mutex);

	if (get_subsystem_state(id) != SUBSYSTEM_STATE_UNLOADED)
		set_subsystem_state(index, SUBSYSTEM_STATE_UNLOADED);

	smw_utils_mutex_unlock(ctx.mutex);
}

static int get_subsystem_default(enum operation_id operation_id,
				 enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OK;

	unsigned int index = operation_id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(subsystem_id);
	OPERATION_ID_ASSERT(operation_id);

	*subsystem_id = database.operation[index];

	if (*subsystem_id == SUBSYSTEM_ID_INVALID)
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

/* The first fields of all Security operations params structures
 * must be the Security operation id
 */
static bool match_operation_id(void *params, void *filter)
{
	return (*((enum operation_id *)params) ==
		*((enum operation_id *)filter));
}

static void *find_operation_params(enum operation_id operation_id,
				   enum subsystem_id subsystem_id)
{
	unsigned int index = subsystem_id;

	struct smw_utils_list *list;

	list = &database.subsystem[index].operations_caps_list;

	return smw_utils_list_find_data(list, &operation_id,
					match_operation_id);
}

int store_operation_params(enum operation_id operation_id, void *params,
			   struct operation_func *func,
			   enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_UNKNOWN_ID;

	unsigned int index = subsystem_id;
	struct smw_utils_list *list;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(subsystem_id);
	OPERATION_ID_ASSERT(operation_id);
	SMW_DBG_ASSERT(func);

	/* Only store the first configuration of a Security operation
	 * for a given Secure subsystem.
	 */
	if (find_operation_params(operation_id, subsystem_id))
		goto end;

	list = &database.subsystem[index].operations_caps_list;
	if (!smw_utils_list_append_data(list, params, func->destroy,
					func->print)) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	status = SMW_STATUS_OK;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_subsystem_id(const char *name, enum subsystem_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * If name is NULL, require the default subsytem.
	 * Hence, set the id as invalid by default.
	 */
	*id = SUBSYSTEM_ID_INVALID;

	if (name)
		status = smw_utils_get_string_index(name, subsystem_names,
						    SUBSYSTEM_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int get_load_method_id(const char *name, enum load_method_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(name);

	if (!SMW_UTILS_STRLEN(name))
		*id = LOAD_METHOD_ID_DEFAULT;
	else
		status = smw_utils_get_string_index(name, load_method_names,
						    LOAD_METHOD_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int get_operation_id(const char *name, enum operation_id *id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_get_string_index(name, operation_names,
					    OPERATION_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__attribute__((weak)) void print_database(void)
{
}

int smw_config_get_subsystem_caps(enum subsystem_id *subsystem_id,
				  enum operation_id operation_id, void **params)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	SMW_DBG_ASSERT(subsystem_id);

	if (*subsystem_id == SUBSYSTEM_ID_INVALID) {
		status = get_subsystem_default(operation_id, subsystem_id);
		if (status != SMW_STATUS_OK)
			goto end;
	}

	SMW_DBG_PRINTF(DEBUG, "Secure subsystem id: %d\n", *subsystem_id);

	*params = find_operation_params(operation_id, *subsystem_id);

	if (!*params)
		status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool check_id(unsigned int id, unsigned long bitmap)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return get_bit(bitmap, sizeof(bitmap) << 3, id);
}

struct operation_func *smw_config_get_operation_func(enum operation_id id)
{
	unsigned int index;

	SMW_DBG_TRACE_FUNCTION_CALL;

	OPERATION_ID_ASSERT(id);

	index = id;
	return operation_func[index]();
}

struct subsystem_func *smw_config_get_subsystem_func(enum subsystem_id id)
{
	unsigned int index;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	index = id;
	return subsystem_func[index]();
}

const char *smw_config_get_operation_name(enum operation_id id)
{
	unsigned int index;

	SMW_DBG_TRACE_FUNCTION_CALL;

	OPERATION_ID_ASSERT(id);

	index = id;
	return operation_names[index];
}

const char *smw_config_get_subsystem_name(enum subsystem_id id)
{
	unsigned int index;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	index = id;
	return subsystem_names[index];
}

void load_subsystems(void)
{
	int status;

	unsigned int i;
	struct subsystem_func *func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		if (is_subsystem_configured(i) &&
		    get_subsystem_load_method_id(i) ==
			    LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD) {
			SMW_DBG_ASSERT(get_subsystem_state(i) ==
				       SUBSYSTEM_STATE_UNLOADED);
			func = smw_config_get_subsystem_func(i);
			SMW_DBG_ASSERT(func);
			if (func->load) {
				status = func->load();
				SMW_DBG_PRINTF_COND(ERROR,
						    status != SMW_STATUS_OK,
						    "Failed to load %s\n",
						    subsystem_names[i]);
			} else {
				status = SMW_STATUS_OK;
			}
			if (status == SMW_STATUS_OK)
				set_subsystem_state(i, SUBSYSTEM_STATE_LOADED);
		}
	}
}

void unload_subsystems(void)
{
	int status;

	unsigned int i;

	struct subsystem_func *func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		if (is_subsystem_configured(i) &&
		    get_subsystem_state(i) == SUBSYSTEM_STATE_LOADED) {
			func = smw_config_get_subsystem_func(i);
			SMW_DBG_ASSERT(func);
			if (func->unload) {
				status = func->unload();
				SMW_DBG_PRINTF_COND(ERROR,
						    status != SMW_STATUS_OK,
						    "Failed to unload %s\n",
						    subsystem_names[i]);
			} else {
				status = SMW_STATUS_OK;
			}
			if (status == SMW_STATUS_OK)
				set_subsystem_state(i,
						    SUBSYSTEM_STATE_UNLOADED);
		}
	}
}

int smw_config_load_subsystem(enum subsystem_id id)
{
	int status = SMW_STATUS_OK;

	enum subsystem_state state;
	enum load_method_id load_method_id;
	struct subsystem_func *func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	smw_utils_mutex_lock(ctx.mutex);

	state = get_subsystem_state(id);
	load_method_id = get_subsystem_load_method_id(id);
	func = smw_config_get_subsystem_func(id);

	if (!is_subsystem_configured(id)) {
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

	switch (state) {
	case SUBSYSTEM_STATE_LOADED:
		break;

	case SUBSYSTEM_STATE_UNLOADED:
		switch (load_method_id) {
		case LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD:
			status = SMW_STATUS_SUBSYSTEM_LOAD_FAILURE;
			goto end;

		case LOAD_METHOD_ID_AT_FIRST_CALL_LOAD:
		case LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION:
			if (func && func->load)
				status = func->load();
			if (status != SMW_STATUS_OK)
				goto end;
			set_subsystem_state(id, SUBSYSTEM_STATE_LOADED);
			break;

		default:
			break;
		}
		break;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown secure subsystem state: %d\n",
			       state);
		SMW_DBG_ASSERT(0);
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_unload_subsystem(enum subsystem_id id)
{
	int status = SMW_STATUS_OK;

	enum subsystem_state state;
	enum load_method_id load_method_id;
	struct subsystem_func *func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	smw_utils_mutex_lock(ctx.mutex);

	state = get_subsystem_state(id);
	load_method_id = get_subsystem_load_method_id(id);
	func = smw_config_get_subsystem_func(id);

	if (!is_subsystem_configured(id)) {
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

	switch (state) {
	case SUBSYSTEM_STATE_LOADED:
		switch (load_method_id) {
		case LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD:
		case LOAD_METHOD_ID_AT_FIRST_CALL_LOAD:
			break;

		case LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION:
			if (func && func->unload)
				status = func->unload();
			if (status != SMW_STATUS_OK)
				goto end;
			set_subsystem_state(id, SUBSYSTEM_STATE_UNLOADED);
			break;

		default:
			break;
		}
		break;

	case SUBSYSTEM_STATE_UNLOADED:
		goto end;

	default:
		SMW_DBG_PRINTF(ERROR, "Unknown secure subsystem state: %d\n",
			       state);
		SMW_DBG_ASSERT(0);
		status = SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED;
		goto end;
	}

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
