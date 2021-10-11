// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "smw_status.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "operations.h"
#include "subsystems.h"
#include "config.h"
#include "name.h"

#include "common.h"
#include "tag.h"

#define SMW_CONFIG_PARSER_VERSION 1

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

bool get_tag_prefix(char *tag, unsigned int length, const char *suffix)
{
	bool match = false;

	unsigned int suffix_length = SMW_UTILS_STRLEN(suffix);

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (length > suffix_length &&
	    !SMW_UTILS_STRNCMP(tag + length - suffix_length, suffix,
			       suffix_length)) {
		match = true;

		/* Remove suffix from tag */
		*(tag + length - suffix_length) = 0;

		SMW_DBG_PRINTF(INFO, "Algo: %s\n", tag);
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

void skip_insignificant_chars(char **start, char *end)
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

int read_unsigned_integer(char **start, char *end, unsigned int *dest)
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
		if (*dest > UINT_MAX / 10) {
			status = SMW_STATUS_TOO_LARGE_NUMBER;
			goto end;
		}
		temp = *dest * 10;

		if (temp > UINT_MAX - (*cur - '0')) {
			status = SMW_STATUS_TOO_LARGE_NUMBER;
			goto end;
		}
		temp += (*cur++ - '0');

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

int read_range(char **start, char *end, struct range *range)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	unsigned int m;

	SMW_DBG_TRACE_FUNCTION_CALL;

	while ((cur < end) && (semicolon != *cur)) {
		m = 0;
		if (colon != *cur) {
			status = read_unsigned_integer(&cur, end, &m);
			if (status != SMW_STATUS_OK)
				goto end;
		}
		SMW_DBG_PRINTF(INFO, "Min: %d\n", m);

		range->min = m;

		skip_insignificant_chars(&cur, end);

		if (colon != *cur) {
			status = SMW_STATUS_SYNTAX_ERROR;
			goto end;
		}
		cur++;

		skip_insignificant_chars(&cur, end);

		m = UINT_MAX;
		if (semicolon != *cur) {
			status = read_unsigned_integer(&cur, end, &m);
			if (status != SMW_STATUS_OK)
				goto end;
		}
		SMW_DBG_PRINTF(INFO, "Max: %d\n", m);

		range->max = m;

		skip_insignificant_chars(&cur, end);
	}

	if (semicolon == *cur)
		cur++;

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

	skip_insignificant_chars(&cur, end);

	if (separator == *cur)
		cur++;
	else
		status = SMW_STATUS_SYNTAX_ERROR;

	*start = cur;

end:
	*p = 0;

	SMW_DBG_PRINTF(VERBOSE, "%s decoded %s\n", __func__, dest);
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int read_params_name(char **start, char *end, char *dest)
{
	return read_string(start, end, dest, SMW_CONFIG_MAX_PARAMS_NAME_LENGTH,
			   equal);
}

int skip_param(char **start, char *end)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_PRINTF(INFO, "Skipped parameters: ");
	while ((cur < end) && (semicolon != *cur)) {
		if (open_square_bracket == *cur ||
		    close_square_bracket == *cur || equal == *cur) {
			status = SMW_STATUS_SYNTAX_ERROR;
			goto end;
		}

		SMW_DBG_PRINTF(INFO, "%c", *cur);

		cur++;
		skip_insignificant_chars(&cur, end);
	}
	SMW_DBG_PRINTF(INFO, "\n");
	if (semicolon == *cur)
		cur++;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int read_names(char **start, char *end, unsigned long *bitmap,
	       const char *const array[], unsigned int size)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	char buffer[SMW_CONFIG_MAX_STRING_LENGTH + 1];
	unsigned int id;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*bitmap = 0;

	while ((cur < end) && (semicolon != *cur)) {
		status = read_string(&cur, end, buffer,
				     SMW_CONFIG_MAX_STRING_LENGTH, colon);
		/* The end of the names list has been reached */
		if (status == SMW_STATUS_SYNTAX_ERROR && semicolon == *cur)
			status = SMW_STATUS_OK;
		if (status != SMW_STATUS_OK)
			goto end;
		SMW_DBG_PRINTF(INFO, "Value: %s\n", buffer);

		status = smw_utils_get_string_index(buffer, array, size, &id);
		if (status != SMW_STATUS_OK)
			goto end;
		set_bit(bitmap, sizeof(bitmap) << 3, id);

		skip_insignificant_chars(&cur, end);
	}

	if (semicolon == *cur)
		cur++;

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static bool read_operation(char **start, char *end,
			   enum subsystem_id subsystem_id, int *return_status)
{
	bool skip = false;

	int status = SMW_STATUS_OK;
	char *cur = *start;
	char buffer[SMW_CONFIG_MAX_STRING_LENGTH + 1];
	enum operation_id operation_id = OPERATION_ID_INVALID;
	struct operation_func *func;
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
	if (status != SMW_STATUS_OK) {
		/* Skip unknown Security Operation without error */
		if (status == SMW_STATUS_UNKNOWN_NAME)
			skip = true;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "Security operation id: %d\n", operation_id);

	skip_insignificant_chars(&cur, end);

	/* Security operation params functions */
	func = get_operation_func(operation_id);

	SMW_DBG_PRINTF(DEBUG, "Security operation params functions: %p\n",
		       func);
	if (func->read)
		status = func->read(&cur, end, &params);
	if (status != SMW_STATUS_OK)
		goto end;

	status = store_operation_params(operation_id, params, func,
					subsystem_id);
	if (status != SMW_STATUS_OK) {
		SMW_UTILS_FREE(params);
		goto end;
	}

	*start = cur;

end:
	if (return_status)
		*return_status = status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned status: %d\n", __func__, status);
	SMW_DBG_PRINTF(VERBOSE, "%s returned %s\n", __func__,
		       skip ? "TRUE" : "FALSE");
	return skip;
}

static bool read_subsystem(char **start, char *end, int *return_status)
{
	bool skip = false;

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
	status = smw_config_get_subsystem_id(buffer, &subsystem_id);
	if (status != SMW_STATUS_OK) {
		/* Skip unknown Secure Subsystem without error */
		if (status == SMW_STATUS_UNKNOWN_NAME)
			skip = true;
		goto end;
	}
	SMW_DBG_PRINTF(DEBUG, "Secure subsystem id: %d\n", subsystem_id);

	skip_insignificant_chars(&cur, end);

	/* Secure Subsystem start/stop method name */
	status = read_string(&cur, end, buffer,
			     SMW_CONFIG_MAX_LOAD_METHOD_NAME_LENGTH, semicolon);
	if (status == SMW_STATUS_SYNTAX_ERROR && open_square_bracket == *cur &&
	    !SMW_UTILS_STRLEN(buffer))
		status = SMW_STATUS_OK;
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(INFO, "Start/stop method name: %s\n", buffer);

	/* Secure Subsystem start/stop method id */
	status = get_load_method_id(buffer, &load_method_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(DEBUG, "Start/stop method id: %d\n", subsystem_id);

	status = set_subsystem_load_method(subsystem_id, load_method_id);
	if (status != SMW_STATUS_OK)
		goto end;

	skip_insignificant_chars(&cur, end);

	/* List of Security operations */
	while (cur < end) {
		/* Security operation tag */
		if (!detect_tag(&cur, end, operation_tag)) {
			if (detect_tag(&cur, end, subsystem_tag)) {
				cur -= SMW_UTILS_STRLEN(subsystem_tag);
				break;
			}
			status = SMW_STATUS_INVALID_TAG;
			goto end;
		}

		skip_insignificant_chars(&cur, end);

		if (read_operation(&cur, end, subsystem_id, &status)) {
			skip_operation(&cur, end);
			status = SMW_STATUS_OK;
		}

		if (status != SMW_STATUS_OK)
			goto end;

		skip_insignificant_chars(&cur, end);
	}

	set_subsystem_configured(subsystem_id);

	*start = cur;

end:
	if (return_status)
		*return_status = status;

	SMW_DBG_PRINTF(VERBOSE, "%s returned status: %d\n", __func__, status);
	SMW_DBG_PRINTF(VERBOSE, "%s returned %s\n", __func__,
		       skip ? "TRUE" : "FALSE");
	return skip;
}

static int get_psa_default_subsystem(char **start, char *end)
{
	int status = SMW_STATUS_OK;

	char *cur = *start;
	char buffer[SMW_CONFIG_MAX_SUBSYSTEM_NAME_LENGTH + 1];
	enum subsystem_id subsystem_id = SUBSYSTEM_ID_INVALID;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!detect_tag(&cur, end, psa_default_tag))
		goto end;

	skip_insignificant_chars(&cur, end);

	if (equal != *cur) {
		status = SMW_STATUS_SYNTAX_ERROR;
		goto end;
	}
	cur++;

	skip_insignificant_chars(&cur, end);

	status = read_string(&cur, end, buffer,
			     SMW_CONFIG_MAX_SUBSYSTEM_NAME_LENGTH, semicolon);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(INFO, "PSA default secure subsystem name: %s\n", buffer);

	/* Secure Subsystem id */
	status = smw_config_get_subsystem_id(buffer, &subsystem_id);
	if (status != SMW_STATUS_OK)
		goto end;

	SMW_DBG_PRINTF(DEBUG, "PSA default secure subsystem id: %d\n",
		       subsystem_id);

	set_psa_default_subsystem(subsystem_id);

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
		status = SMW_STATUS_INVALID_TAG;
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

	if (version == 0 || /* No backward compatibility with version 0 */
	    version > SMW_CONFIG_PARSER_VERSION) {
		status = SMW_STATUS_INVALID_VERSION;
		goto end;
	}

	*start = cur;

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int parse(char *buffer, unsigned int size, unsigned int *offset)
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

	skip_insignificant_chars(&cur, end);

	/* PSA default subsystem */
	status = get_psa_default_subsystem(&cur, end);
	if (status != SMW_STATUS_OK)
		goto end;

	/* List of Secure Subsystems */
	while (cur < end) {
		/* Secure Subsystem tag */
		if (!detect_tag(&cur, end, subsystem_tag)) {
			status = SMW_STATUS_INVALID_TAG;
			goto end;
		}

		skip_insignificant_chars(&cur, end);

		if (read_subsystem(&cur, end, &status)) {
			skip_subsystem(&cur, end);
			status = SMW_STATUS_OK;
		}

		if (status != SMW_STATUS_OK)
			goto end;

		skip_insignificant_chars(&cur, end);
	}

end:
	if (status != SMW_STATUS_OK) {
		if (*offset) {
			*offset = (unsigned int)(cur - buffer);
			SMW_DBG_PRINTF(ERROR,
				       "Error detected nearly after offset:%d\n",
				       *offset);
		}
		SMW_DBG_PRINTF_COND(ERROR, cur < end,
				    "Ignore end of file:\n%.*s\n",
				    (unsigned int)(end - cur), cur);

		init_database(true);
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
