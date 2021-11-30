// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "compiler.h"
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

void init_key_params(struct op_key *key)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	key->type_bitmap = 0;
	for (i = 0; i < ARRAY_SIZE(key->size_range); i++) {
		key->size_range[i].min = 0;
		key->size_range[i].max = UINT_MAX;
	}
}

static void init_subsystem(struct subsystem *subsystem)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	subsystem->configured = false;
	subsystem->state = SUBSYSTEM_STATE_UNLOADED;
	subsystem->load_method_id = LOAD_METHOD_ID_INVALID;
}

static void init_operation(struct operation *operation, bool reset)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (reset)
		smw_utils_list_destroy(&operation->subsystems_list);
	else
		smw_utils_list_init(&operation->subsystems_list);

	smw_utils_list_print(&operation->subsystems_list);
}

void init_database(bool reset)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	database.psa_default_subsystem_id = SUBSYSTEM_ID_INVALID;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++)
		init_subsystem(&database.subsystem[i]);

	for (i = 0; i < OPERATION_ID_NB; i++)
		init_operation(&database.operation[i], reset);
}

void set_psa_default_subsystem(enum subsystem_id id)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	database.psa_default_subsystem_id = id;
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

bool is_subsystem_configured(enum subsystem_id id)
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

int set_subsystem_load_method(enum subsystem_id id,
			      enum load_method_id load_method_id)
{
	int status = SMW_STATUS_OK;
	unsigned int index = id;
	struct subsystem *subsystem;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	subsystem = &database.subsystem[index];

	if (load_method_id != LOAD_METHOD_ID_INVALID) {
		if (subsystem->load_method_id == LOAD_METHOD_ID_INVALID)
			/* Load/unload method not specified yet */
			subsystem->load_method_id = load_method_id;
		else
			/* Load/unload method already specified */
			status = SMW_STATUS_LOAD_METHOD_DUPLICATE;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static enum load_method_id get_subsystem_load_method_id(enum subsystem_id id)
{
	enum load_method_id load_method_id;
	unsigned int index = id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(id);

	load_method_id = database.subsystem[index].load_method_id;
	if (load_method_id == LOAD_METHOD_ID_INVALID)
		load_method_id = LOAD_METHOD_ID_DEFAULT;

	return load_method_id;
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

int store_operation_params(enum operation_id operation_id, void *params,
			   struct operation_func *func,
			   enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_OK;

	unsigned int index = operation_id;
	struct smw_utils_list *list;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SUBSYSTEM_ID_ASSERT(subsystem_id);
	OPERATION_ID_ASSERT(operation_id);
	SMW_DBG_ASSERT(func);

	list = &database.operation[index].subsystems_list;
	if (!smw_utils_list_append_data(list, params, subsystem_id,
					func->print))
		status = SMW_STATUS_ALLOC_FAILURE;

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_get_subsystem_id(const char *name, enum subsystem_id *id)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/*
	 * If name is NULL, require the default subsystem.
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
		*id = LOAD_METHOD_ID_INVALID;
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

__weak void print_key_params(struct op_key *key)
{
	(void)key;
}

__weak void print_database(void)
{
}

void merge_key_params(struct op_key *key_caps, struct op_key *key_params)
{
	struct range *caps_range = key_caps->size_range;
	struct range *params_range = key_params->size_range;

	unsigned int i;

	for (i = 0; i < SMW_CONFIG_KEY_TYPE_ID_NB; i++) {
		if (check_id(i, key_params->type_bitmap)) {
			if (!check_id(i, key_caps->type_bitmap)) {
				caps_range[i] = params_range[i];
			} else {
				if (caps_range[i].min > params_range[i].min)
					caps_range[i].min = params_range[i].min;
				if (caps_range[i].max < params_range[i].max)
					caps_range[i].max = params_range[i].max;
			}
		}
	}

	key_caps->type_bitmap |= key_params->type_bitmap;
}

int smw_config_select_subsystem(enum operation_id operation_id, void *args,
				enum subsystem_id *subsystem_id)
{
	int status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	struct operation_func *operation_func;
	int (*check_subsystem_caps)(void *args, void *params);
	unsigned int index = operation_id;

	struct smw_utils_list *list;
	unsigned int *ref = NULL;
	struct node *node = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(subsystem_id);

	operation_func = get_operation_func(operation_id);
	SMW_DBG_ASSERT(operation_func);

	check_subsystem_caps = operation_func->check_subsystem_caps;
	SMW_DBG_ASSERT(check_subsystem_caps);

	list = &database.operation[index].subsystems_list;

	if (*subsystem_id != SUBSYSTEM_ID_INVALID)
		ref = subsystem_id;

	smw_utils_mutex_lock(ctx.mutex);

	node = smw_utils_list_find_first(list, ref);
	while (node) {
		status = check_subsystem_caps(args,
					      smw_utils_list_get_data(node));

		if (status == SMW_STATUS_OK) {
			*subsystem_id = smw_utils_list_get_ref(node);
			break;
		}

		node = smw_utils_list_find_next(node, ref);
	}

	smw_utils_mutex_unlock(ctx.mutex);

	return status;
}

int get_operation_params(enum operation_id operation_id,
			 enum subsystem_id subsystem_id, void *params)
{
	int status = SMW_STATUS_OPERATION_NOT_CONFIGURED;

	struct operation_func *operation_func;
	unsigned int index = operation_id;

	struct smw_utils_list *list;
	struct node *node = NULL;
	unsigned int *key = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(params);
	OPERATION_ID_ASSERT(operation_id);

	SMW_DBG_PRINTF(DEBUG, "Security operation id: %d\n", operation_id);
	SMW_DBG_PRINTF(DEBUG, "Secure subsystem id: %d\n", subsystem_id);

	operation_func = get_operation_func(operation_id);

	list = &database.operation[index].subsystems_list;

	if (subsystem_id != SUBSYSTEM_ID_INVALID)
		key = &subsystem_id;

	smw_utils_mutex_lock(ctx.mutex);

	node = smw_utils_list_find_first(list, key);
	if (node)
		status = SMW_STATUS_OK;

	while (node) {
		operation_func->merge(params, smw_utils_list_get_data(node));

		node = smw_utils_list_find_next(node, key);
	}

	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

bool check_id(unsigned int id, unsigned long bitmap)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return get_bit(bitmap, sizeof(bitmap) << 3, id);
}

bool check_size(unsigned int size, struct range *range)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return ((size >= range->min) && (size <= range->max)) ? true : false;
}

bool check_key(struct smw_keymgr_identifier *key_identifier,
	       struct op_key *key_params)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!check_id(key_identifier->type_id, key_params->type_bitmap) ||
	    !check_size(key_identifier->security_size,
			&key_params->size_range[key_identifier->type_id]))
		return false;

	return true;
}

struct operation_func *get_operation_func(enum operation_id id)
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

	OPERATION_ID_ASSERT(id);

	index = id;
	return operation_names[index];
}

const char *smw_config_get_subsystem_name(enum subsystem_id id)
{
	unsigned int index;

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
