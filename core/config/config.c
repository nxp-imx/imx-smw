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

#include "subsystems.h"
#include "operations.h"
#include "config.h"

#include "subsystems_apis.h"
#include "operations_apis.h"

#define SMW_CONFIG_PARSER_VERSION 0

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

struct {
	void *mutex;
	unsigned int load_count;
} ctx = { .mutex = NULL, .load_count = 0 };

enum load_method_id {
	/* Load / unload methods */
	LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD,
	LOAD_METHOD_ID_AT_FIRST_CALL_LOAD,
	LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION,
	LOAD_METHOD_ID_NB,
	LOAD_METHOD_ID_INVALID
};

#define LOAD_METHOD_ID_DEFAULT LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD

enum subsystem_state { SUBSYSTEM_STATE_UNLOADED, SUBSYSTEM_STATE_LOADED };

struct subsystem {
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
	unsigned long operations_bitmap;
	struct smw_utils_list operations_caps_list;
};

struct database {
	struct subsystem subsystem[SUBSYSTEM_ID_NB];
	enum subsystem_id operation[OPERATION_ID_NB];
};

/* Specified separators */
static const char open_square_bracket = '[';
static const char close_square_bracket = ']';
static const char semicolon = ';';
static const char equal = '=';
static const char colon = ':';

/* Whitespaces */
static const char space = ' ';
static const char carriage_return = '\r';
static const char new_line = '\n';
static const char tab = '\t';

/* Sections tags */
static const char *subsystem_tag = "[SECURE_SUBSYSTEM]";
static const char *operation_tag = "[SECURITY_OPERATION]";

/* Parameters tags */
static const char *version_tag = "VERSION";
static const char *default_tag = "DEFAULT;";

static const char *const load_method_names[] = {
	[LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD] = "AT_CONFIG_LOAD_UNLOAD",
	[LOAD_METHOD_ID_AT_FIRST_CALL_LOAD] = "AT_FIRST_CALL_LOAD",
	[LOAD_METHOD_ID_AT_CONTEXT_CREATION_DESTRUCTION] =
		"AT_CONTEXT_CREATION_DESTRUCTION"
};

static struct database database;

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

static void init_database(bool reset)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++)
		init_subsystem(&database.subsystem[i], reset);

	for (i = 0; i < OPERATION_ID_NB; i++)
		database.operation[i] = SUBSYSTEM_ID_INVALID;
}

int smw_config_init(void)
{
	int status = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_mutex_init(&ctx.mutex);

	if (!status)
		init_database(false);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_deinit(void)
{
	int status = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = smw_utils_mutex_destroy(&ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void set_bit(unsigned long *bitmap, unsigned int bit_size,
		    unsigned int offset)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(offset < bit_size);
	*bitmap |= (1 << offset);
}

static void set_subsystem_configured(enum subsystem_id id)
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

static void set_subsystem_load_method(enum subsystem_id id,
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

static void set_subsystem_operation_bitmap(enum subsystem_id subsystem_id,
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

static void set_subsystem_default(enum operation_id operation_id,
				  enum subsystem_id subsystem_id,
				  bool is_default)
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

static int store_operation_params(enum operation_id operation_id, void *params,
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

static bool is_string_delimiter(char c)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (open_square_bracket == c)
		return true;
	if (close_square_bracket == c)
		return true;
	if (semicolon == c)
		return true;
	if (equal == c)
		return true;
	if (colon == c)
		return true;
	if (space == c)
		return true;
	if (carriage_return == c)
		return true;
	if (new_line == c)
		return true;
	if (tab == c)
		return true;

	return false;
}

static bool detect_tag(char **start, char *end, const char *tag)
{
	bool match = false;

	unsigned int tag_length = SMW_UTILS_STRLEN(tag);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (((*start + tag_length - 1) < end) &&
	    !SMW_UTILS_STRNCMP(tag, *start, tag_length)) {
		match = true;
		*start += tag_length;
		SMW_DBG_PRINTF(INFO, "Tag: %s\n", tag);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %s\n", __func__,
		       match ? "true" : "false");
	return match;
}

static unsigned int skip_comments(char **start, char *end)
{
	unsigned int count = 0;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* If the next two chars are slash and asterisk,
	 * move *start after the next asterisk followed by slash chars.
	 */
	if (((cur + 2) < end) && ('/' == *cur) && ('*' == *(cur + 1))) {
		cur += 2;

		while (cur < end) {
			if (('*' == *cur) && ((cur + 1) < end) &&
			    ('/' == *(cur + 1))) {
				cur += 2;
				break;
			}
			cur++;
		}

		SMW_DBG_PRINTF(DEBUG, "Skip comment: %.*s\n",
			       (unsigned int)(cur - *start), *start);
	}

	count = (unsigned int)(cur - *start);
	*start = cur;

	SMW_DBG_PRINTF(VERBOSE, "%s returned count: %d\n", __func__, count);
	return count;
}

static unsigned int skip_whitespaces(char **start, char *end)
{
	unsigned int count = 0;
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (cur < end) {
		if (space != *cur && carriage_return != *cur &&
		    new_line != *cur && tab != *cur)
			break;
		cur++;
	}

	count = (unsigned int)(cur - *start);
	*start = cur;

	SMW_DBG_PRINTF(VERBOSE, "%s returned count: %d\n", __func__, count);
	return count;
}

static void skip_insignificant_chars(char **start, char *end)
{
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (cur < end) {
		if (!skip_comments(&cur, end) && !skip_whitespaces(&cur, end))
			break;
	}

	*start = cur;
}

static void skip_operation(char **start, char *end)
{
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (cur < end) {
		if (*operation_tag != *cur) {
			cur++;
			continue;
		}
		if (*subsystem_tag != *cur) {
			cur++;
			continue;
		}
		if (detect_tag(&cur, end, operation_tag)) {
			cur -= SMW_UTILS_STRLEN(operation_tag);
			break;
		}
		if (detect_tag(&cur, end, subsystem_tag)) {
			cur -= SMW_UTILS_STRLEN(subsystem_tag);
			break;
		}
		cur++;
	}

	SMW_DBG_PRINTF(INFO, "Skip security operation: %.*s\n",
		       (unsigned int)(cur - *start), *start);

	*start = cur;
}

static void skip_subsystem(char **start, char *end)
{
	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (cur < end) {
		if (*subsystem_tag != *cur) {
			cur++;
			continue;
		}
		if (detect_tag(&cur, end, subsystem_tag)) {
			cur -= SMW_UTILS_STRLEN(subsystem_tag);
			break;
		}
		cur++;
	}

	SMW_DBG_PRINTF(INFO, "Skip secure subsystem: %.*s\n",
		       (unsigned int)(cur - *start), *start);

	*start = cur;
}

static int read_unsigned_integer(char **start, char *end, unsigned int *dest)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	unsigned int temp;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*dest = 0;

	if (cur >= end) {
		status = SMW_STATUS_EOF;
		goto end;
	}

	if ('+' == *cur)
		cur++;

	if ((*cur < '0') || (*cur > '9')) {
		status = SMW_STATUS_SYNTAX_ERROR;
		goto end;
	}

	while ((*cur >= '0') && (*cur <= '9') && (cur < end)) {
		temp = *dest * 10 + (*cur++ - '0');
		if (temp < *dest) {
			status = SMW_STATUS_TOO_LARGE_NUMBER;
			goto end;
		}
		*dest = temp;
	}

	if (cur >= end) {
		status = SMW_STATUS_EOF;
		goto end;
	}

	skip_insignificant_chars(&cur, end);

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int read_string(char **start, char *end, char *dest,
		       unsigned int max_len, char separator)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	char *p = dest;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while (((unsigned int)(p - dest) < max_len) &&
	       !is_string_delimiter(*cur)) {
		if (cur >= end) {
			status = SMW_STATUS_EOF;
			goto end;
		}

		*p++ = *cur++;
	}
	*p = 0;

	skip_insignificant_chars(&cur, end);

	if (separator == *cur)
		cur++;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s decoded %s\n", __func__, dest);
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_id(const char *name, const char *const array[],
		  unsigned int size, unsigned int *id)
{
	int status = SMW_STATUS_UNKNOWN_NAME;

	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < size; i++) {
		if (*array[i]) {
			if (!SMW_UTILS_STRCMP(array[i], name)) {
				status = SMW_STATUS_OK;
				*id = i;
				break;
			}
		}
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_subsystem_id(const char *name, enum subsystem_id *id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_id(name, subsystem_names, SUBSYSTEM_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_load_method_id(const char *name, enum load_method_id *id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!SMW_UTILS_STRLEN(name)) {
		*id = LOAD_METHOD_ID_DEFAULT;
		return SMW_STATUS_OK;
	}

	status = get_id(name, load_method_names, LOAD_METHOD_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int get_operation_id(const char *name, enum operation_id *id)
{
	int status;

	SMW_DBG_TRACE_FUNCTION_CALL;

	status = get_id(name, operation_names, OPERATION_ID_NB, id);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_operation(char **start, char *end,
			   enum subsystem_id subsystem_id)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	char buffer[SMW_CONFIG_MAX_STRING_LENGTH + 1];
	enum operation_id operation_id = OPERATION_ID_INVALID;
	bool subsystem_is_default = false;
	unsigned int index;
	struct operation_func *func = NULL;
	void *params = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Security operation name */
	status = read_string(&cur, end, buffer,
			     SMW_CONFIG_MAX_OPERATION_NAME_LENGTH, semicolon);
	if (status != SMW_STATUS_OK)
		goto end;
	SMW_DBG_PRINTF(INFO, "Security operation name: %s\n", buffer);

	/* Security operation id */
	status = get_operation_id(buffer, &operation_id);
	if (status != SMW_STATUS_OK)
		goto end;
	SMW_DBG_PRINTF(DEBUG, "Security operation id: %d\n", operation_id);

	skip_insignificant_chars(&cur, end);

	/* Security operation default */
	subsystem_is_default = detect_tag(&cur, end, default_tag);
	if (subsystem_is_default)
		SMW_DBG_PRINTF(INFO, "Secure subsystem (%d) is DEFAULT\n",
			       subsystem_id);

	skip_insignificant_chars(&cur, end);

	/* Security operation params functions */
	index = operation_id;
	func = operation_func[index]();

	SMW_DBG_PRINTF(DEBUG, "Security operation params functions: %p\n",
		       func);
	if (func->decode)
		status = func->decode(&cur, end, operation_id, &params);
	if (status != SMW_STATUS_OK)
		goto end;

	status = store_operation_params(operation_id, params, func,
					subsystem_id);
	if (status != SMW_STATUS_OK) {
		if (func->destroy)
			func->destroy(params);
		SMW_UTILS_FREE(params);
		goto end;
	}

	set_subsystem_operation_bitmap(subsystem_id, operation_id);
	set_subsystem_default(operation_id, subsystem_id, subsystem_is_default);

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int store_subsystem(char **start, char *end)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	char buffer[SMW_CONFIG_MAX_STRING_LENGTH + 1];

	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;
	enum load_method_id load_method_id = LOAD_METHOD_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Secure Subsystem name */
	status = read_string(&cur, end, buffer,
			     SMW_CONFIG_MAX_SUBSYSTEM_NAME_LENGTH, semicolon);
	if (status != SMW_STATUS_OK)
		goto end;
	SMW_DBG_PRINTF(INFO, "Secure subsystem name: %s\n", buffer);

	/* Secure Subsystem id */
	status = get_subsystem_id(buffer, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;
	SMW_DBG_PRINTF(DEBUG, "Secure subsystem id: %d\n", subsystem_id);

	skip_insignificant_chars(&cur, end);

	/* Secure Subsystem start/stop method name */
	status = read_string(&cur, end, buffer,
			     SMW_CONFIG_MAX_LOAD_METHOD_NAME_LENGTH, semicolon);
	if (status != SMW_STATUS_OK)
		goto end;
	SMW_DBG_PRINTF(INFO, "Start/stop method name: %s\n", buffer);

	/* Secure Subsystem start/stop method id */
	status = get_load_method_id(buffer, &load_method_id);
	if (status != SMW_STATUS_OK)
		goto end;
	SMW_DBG_PRINTF(DEBUG, "Start/stop method id: %d\n", subsystem_id);

	/* List of Security operations */
	while (cur < end) {
		skip_insignificant_chars(&cur, end);

		/* Security operation tag */
		if (!detect_tag(&cur, end, operation_tag))
			break;

		skip_insignificant_chars(&cur, end);

		status = store_operation(&cur, end, subsystem_id);

		if (status == SMW_STATUS_UNKNOWN_NAME) {
			skip_operation(&cur, end);
			status = SMW_STATUS_OK;
		}

		if (status != SMW_STATUS_OK)
			goto end;
	}

	set_subsystem_configured(subsystem_id);
	set_subsystem_load_method(subsystem_id, load_method_id);

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int verify_version(char **start, char *end)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	unsigned int version = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!detect_tag(&cur, end, version_tag)) {
		status = SMW_STATUS_SYNTAX_ERROR;
		goto end;
	}

	skip_insignificant_chars(&cur, end);

	if (equal != *cur) {
		status = SMW_STATUS_SYNTAX_ERROR;
		goto end;
	}
	cur++;

	skip_insignificant_chars(&cur, end);

	status = read_unsigned_integer(&cur, end, &version);
	if (status != SMW_STATUS_OK)
		goto end;

	if (semicolon != *cur) {
		status = SMW_STATUS_SYNTAX_ERROR;
		goto end;
	}
	cur++;

	SMW_DBG_PRINTF(INFO, "Version: %d\n", version);

	if (version > SMW_CONFIG_PARSER_VERSION)
		return SMW_STATUS_INVALID_VERSION;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int parse(char *buffer, unsigned int size)
{
	int status = SMW_STATUS_OK;

	char *cur = buffer;
	char *end = buffer + size;

	SMW_DBG_TRACE_FUNCTION_CALL;

	skip_insignificant_chars(&cur, end);

	/* Version */
	status = verify_version(&cur, end);
	if (status != SMW_STATUS_OK)
		goto end;

	/* List of Secure Subsystems */
	while (cur < end) {
		skip_insignificant_chars(&cur, end);

		/* Secure Subsystem tag */
		if (!detect_tag(&cur, end, subsystem_tag))
			break;

		skip_insignificant_chars(&cur, end);

		status = store_subsystem(&cur, end);

		if (status == SMW_STATUS_UNKNOWN_NAME) {
			skip_subsystem(&cur, end);
			status = SMW_STATUS_OK;
		}

		if (status != SMW_STATUS_OK)
			goto end;
	}

end:
	SMW_DBG_PRINTF_COND(cur < end, DEBUG, "Ignore end of file:\n%.*s\n",
			    (unsigned int)(end - cur), cur);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static void print_database(void)
{
#if defined(ENABLE_TRACE)
	unsigned int i;
	struct subsystem *subsystem;
	bool configured;
	enum subsystem_state state;
	enum load_method_id load_method_id;
	unsigned long operations_bitmap;
	struct smw_utils_list *operations_caps_list;

	SMW_DBG_PRINTF(INFO, "Secure subsystems capabilities:\n");
	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		subsystem = &database.subsystem[i];
		configured = subsystem->configured;
		state = subsystem->state;
		load_method_id = subsystem->load_method_id;
		operations_bitmap = subsystem->operations_bitmap;
		operations_caps_list = &subsystem->operations_caps_list;

		SMW_DBG_PRINTF(INFO,
			       "\n%s%d\n"
			       "%s%s\n"
			       "%s%d\n"
			       "%s%d\n"
			       "%s%lX\n",
			       "    id                : ", i,
			       "    configured        : ",
			       configured ? "true" : "false",
			       "    state             : ", state,
			       "    load/unload method: ", load_method_id,
			       "    operations_bitmap : ", operations_bitmap);
		if (configured)
			smw_utils_list_print(operations_caps_list);
	}
	SMW_DBG_PRINTF(INFO, "Default subsystems:\n");
	for (i = 0; i < OPERATION_ID_NB; i++) {
		SMW_DBG_PRINTF(INFO, "    [%d] = %d\n", i,
			       database.operation[i]);
	}
#endif
}

static int load_subsystems(void)
{
	int status = SMW_STATUS_OK;

	unsigned int i;
	struct subsystem_func *func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		if (is_subsystem_configured(i)) {
			SMW_DBG_ASSERT(get_subsystem_state(i) ==
				       SUBSYSTEM_STATE_UNLOADED);
			if (get_subsystem_load_method_id(i) ==
			    LOAD_METHOD_ID_AT_CONFIG_LOAD_UNLOAD) {
				func = subsystem_func[i]();
				if (func && func->load) {
					status = func->load();
					if (status != SMW_STATUS_OK)
						goto end;
				}
				set_subsystem_state(i, SUBSYSTEM_STATE_LOADED);
			}
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_config_load(char *buffer, unsigned int size)
{
	int status = SMW_STATUS_OK;

	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	if (!ctx.load_count) {
		if (!size || !buffer) {
			status = SMW_STATUS_INVALID_BUFFER;
			goto end;
		}

		status = parse(buffer, size);
		if (status != SMW_STATUS_OK)
			goto end;

		print_database();

		status = load_subsystems();
		if (status != SMW_STATUS_OK) {
			init_database(true);
			goto end;
		}
	}

	ctx.load_count++;

	SMW_DBG_PRINTF(VERBOSE, "%s - Load count: %d\n", __func__,
		       ctx.load_count);

end:
	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static int unload_subsystems(void)
{
	int status = SMW_STATUS_OK;

	unsigned int i;

	struct subsystem_func *func;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < SUBSYSTEM_ID_NB; i++) {
		if (is_subsystem_configured(i)) {
			if (get_subsystem_state(i) == SUBSYSTEM_STATE_LOADED) {
				func = subsystem_func[i]();
				if (func && func->unload) {
					status = func->unload();
					if (status != SMW_STATUS_OK)
						goto end;
				}
				set_subsystem_state(i,
						    SUBSYSTEM_STATE_UNLOADED);
			}
		}
	}

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

void smw_config_unload(void)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	smw_utils_mutex_lock(ctx.mutex);

	if (ctx.load_count == 1) {
		unload_subsystems();

		init_database(true);

		print_database();
	}

	if (ctx.load_count >= 1)
		ctx.load_count--;

	smw_utils_mutex_unlock(ctx.mutex);

	SMW_DBG_PRINTF(VERBOSE, "%s - Load count: %d\n", __func__,
		       ctx.load_count);
}
