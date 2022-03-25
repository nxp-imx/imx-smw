// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <json.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <compiler.h>

#include "json_util.h"
#include "util.h"
#include "util_app.h"
#include "util_list.h"
#include "util_file.h"
#include "util_mutex.h"

/**
 * struct - test_err_case
 * @status: Integer value of 'test_error' json parameter.
 * @string: String value of 'test_error' json parameter presents in test
 *          definition file.
 */
static const struct test_err_case {
	enum arguments_test_err_case status;
	char *string;
} args_test_err_case[] = {
	ENUM_TO_STRING(ARGS_NULL),	   ENUM_TO_STRING(BAD_FORMAT),
	ENUM_TO_STRING(KEY_BUFFER_NULL),   ENUM_TO_STRING(KEY_DESC_ID_NOT_SET),
	ENUM_TO_STRING(KEY_DESC_ID_SET),   ENUM_TO_STRING(KEY_DESC_NULL),
	ENUM_TO_STRING(KEY_DESC_OUT_NULL), ENUM_TO_STRING(NB_ERROR_CASE),
	ENUM_TO_STRING(CTX_NULL),	   ENUM_TO_STRING(CTX_HANDLE_NULL),
	ENUM_TO_STRING(DST_CPY_ARGS_NULL), ENUM_TO_STRING(TLS12_KDF_ARGS_NULL),
};

#define SET_ERR_CODE_AND_NAME(err, name)                                       \
	{                                                                      \
		.code = -(err), .status = name                                 \
	}

const struct error list_err[MAX_TEST_ERROR] = {
	SET_ERR_CODE_AND_NAME(PASSED, "PASSED"),
	SET_ERR_CODE_AND_NAME(FAILED, "FAILED"),
	SET_ERR_CODE_AND_NAME(INTERNAL, "INTERNAL"),
	SET_ERR_CODE_AND_NAME(INTERNAL_OUT_OF_MEMORY, "INTERNAL OUT OF MEMORY"),
	SET_ERR_CODE_AND_NAME(UNDEFINED_CMD, "UNDEFINED COMMAND"),
	SET_ERR_CODE_AND_NAME(MISSING_PARAMS, "MISSING MANDATORY PARAMS"),
	SET_ERR_CODE_AND_NAME(UNKNOWN_RESULT, "UNKNOWN RESULT"),
	SET_ERR_CODE_AND_NAME(API_STATUS_NOK, "API CALL RETURN ERROR"),
	SET_ERR_CODE_AND_NAME(BAD_ARGS, "BAD ARGUMENTS"),
	SET_ERR_CODE_AND_NAME(SUBSYSTEM, "SUBSYSTEM ERROR"),
	SET_ERR_CODE_AND_NAME(NOT_RUN, "NOT RUN"),
	SET_ERR_CODE_AND_NAME(BAD_PARAM_TYPE, "BAD PARAMETER TYPE"),
	SET_ERR_CODE_AND_NAME(VALUE_NOTFOUND, "VALUE NOT FOUND"),
	SET_ERR_CODE_AND_NAME(KEY_NOTFOUND, "KEY NOT FOUND"),
	SET_ERR_CODE_AND_NAME(ERROR_NOT_DEFINED, "TEST ERROR NOT DEFINED"),
	SET_ERR_CODE_AND_NAME(ERROR_SMWLIB_INIT, "SMW LIBRARY INIT ERROR"),
	SET_ERR_CODE_AND_NAME(MUTEX_DESTROY, "MUTEX DESTROY ERROR"),
	SET_ERR_CODE_AND_NAME(COND_DESTROY, "COND DESTROY ERROR"),
	SET_ERR_CODE_AND_NAME(TIMEOUT, "WAIT TIMEOUT ERROR"),
	SET_ERR_CODE_AND_NAME(THREAD_CANCELED, "THREAD HAS BEEN CANCELED"),
	SET_ERR_CODE_AND_NAME(BAD_SUBSYSTEM, "API CALLED UNEXPECTED SUBSYSTEM"),
};

#undef SET_ERR_CODE_AND_NAME

static struct test_data *test_data;

struct test_data *util_get_test(void)
{
	return test_data;
}

struct test_data *util_setup_test(void)
{
	int err = 1;
	struct test_data *test = NULL;

	test = calloc(1, sizeof(*test));
	if (!test)
		return NULL;

	test->lock_dbg = util_mutex_create();
	if (!test->lock_dbg)
		goto exit;

	test->lock_log = util_mutex_create();
	if (!test->lock_log)
		goto exit;

	err = util_app_init(&test->apps);

exit:
	if (err) {
		util_destroy_test(test);
		test = NULL;
	}

	test_data = test;

	return test;
}

void util_destroy_test(struct test_data *test)
{
	int res;

	if (!test)
		return;

	test_data = NULL;

	/* Destroy the debug print mutex and abort if failure */
	res = util_mutex_destroy(&test->lock_dbg);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Destroy mutex error %d", res);
		assert(res == ERR_CODE(PASSED));
	}

	if (test->log)
		(void)fclose(test->log);

	/* Destroy the log file mutex and abort if failure */
	res = util_mutex_destroy(&test->lock_log);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Destroy mutex error %d", res);
		assert(res == ERR_CODE(PASSED));
	}

	if (test->definition)
		json_object_put(test->definition);

	res = util_list_clear(test->apps);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Clear applications list error %d", res);
		assert(res == ERR_CODE(PASSED));
	}

	free(test);
}

int util_string_to_hex(char *string, unsigned char **hex, unsigned int *len)
{
	char tmp[3] = { 0 };
	int i = 0;
	unsigned int j = 0;
	int string_len = 0;

	if (!string || !hex || !len) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	string_len = strlen(string);
	if (string_len % 2) {
		/* String message represents an hexadecimal value */
		DBG_PRINT("String message length must be a multiple of 2");
		return ERR_CODE(BAD_ARGS);
	}

	*len = string_len / 2;

	*hex = malloc(*len);
	if (!*hex) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	for (; i < string_len && j < *len; i += 2, j++) {
		tmp[0] = string[i];
		tmp[1] = string[i + 1];
		(*hex)[j] = strtol(tmp, NULL, 16);
	}

	return ERR_CODE(PASSED);
}

int util_read_json_buffer(char **buf, unsigned int *buf_len,
			  unsigned int *json_len, json_object *obuf)
{
	json_object *otmp;
	char *buf_tmp = NULL;
	int idx = 0;
	int idx_string = 0;
	int nb_entries;
	unsigned int len_tmp = 0;

	if (!buf || !buf_len || !json_len || !obuf) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	switch (json_object_get_type(obuf)) {
	case json_type_array:
		nb_entries = json_object_array_length(obuf);

		otmp = json_object_array_get_idx(obuf, 0);
		if (json_object_get_type(otmp) == json_type_int) {
			/* Buffer length in byte is specified, get it */
			*json_len = json_object_get_int(otmp);
			idx++;
			idx_string = 1;
		}
		for (; idx < nb_entries; idx++) {
			otmp = json_object_array_get_idx(obuf, idx);
			if (json_object_get_type(otmp) != json_type_string) {
				DBG_PRINT("Attributes must be json-c string");
				return ERR_CODE(FAILED);
			}

			len_tmp += json_object_get_string_len(otmp);
		}
		break;

	case json_type_string:
		len_tmp = json_object_get_string_len(obuf);
		otmp = obuf;
		nb_entries = 1;
		break;

	case json_type_int:
		/* Just the buffer length in byte is given, there is no data */
		*json_len = json_object_get_int(obuf);
		nb_entries = 0;
		break;

	default:
		DBG_PRINT("Attributes must be string or an array of strings");
		return ERR_CODE(FAILED);
	}

	*buf_len = len_tmp;

	/* Read data if any */
	if (len_tmp) {
		/* Don't miss the NULL termination */
		buf_tmp = malloc(len_tmp + 1);
		if (!buf_tmp)
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);

		*buf = buf_tmp;
		for (idx = idx_string; idx < nb_entries; idx++) {
			if (nb_entries > 1)
				otmp = json_object_array_get_idx(obuf, idx);

			len_tmp = json_object_get_string_len(otmp);
			if (len_tmp && json_object_get_string(otmp)) {
				memcpy(buf_tmp, json_object_get_string(otmp),
				       len_tmp);
				buf_tmp += len_tmp;
			}
		}

		*buf_tmp = '\0';
	}

	return ERR_CODE(PASSED);
}

int util_read_hex_buffer(unsigned char **hex, unsigned int *length,
			 json_object *params, const char *field)
{
	int ret = ERR_CODE(MISSING_PARAMS);
	json_object *obj;
	char *str = NULL;
	unsigned int len = 0;
	unsigned int json_len = UINT_MAX;

	if (!params || !field || !hex || !length) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (!json_object_object_get_ex(params, field, &obj))
		return ret;

	ret = util_read_json_buffer(&str, &len, &json_len, obj);
	if (ret == ERR_CODE(PASSED)) {
		/* Either test definition specify:
		 * - length != 0 but no data
		 * - length = 0 but data
		 * - no length but data
		 * - length and data
		 */
		if (str)
			ret = util_string_to_hex(str, hex, &len);

		if (json_len != UINT_MAX)
			*length = json_len;
		else
			*length = len;
	}

	if (str)
		free(str);

	return ret;
}

int get_test_name(char **test_name, char *test_definition_file)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int len = 0;
	char *filename;

	if (!test_name || !test_definition_file) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	filename = basename(test_definition_file);
	if (!filename) {
		DBG_PRINT("test definition file name incorrect");
		return res;
	}

	/* First check test definition file extension */
	res = check_file_extension(test_definition_file,
				   DEFINITION_FILE_EXTENSION);
	if (res != ERR_CODE(PASSED))
		return res;

	/*
	 * Extract filename without extension
	 * and build the @test_name null terminated string
	 */
	len = strlen(filename) - strlen(DEFINITION_FILE_EXTENSION);

	*test_name = malloc(len + 1);
	if (!*test_name) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strncpy(*test_name, filename, len);
	(*test_name)[len] = '\0';

	return ERR_CODE(PASSED);
}

int util_read_test_error(enum arguments_test_err_case *error,
			 json_object *params)
{
	int ret = ERR_CODE(PASSED);
	size_t idx;
	char *tst_err = NULL;

	if (!error || !params) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	*error = NOT_DEFINED;

	ret = util_read_json_type(&tst_err, TEST_ERR_OBJ, t_string, params);
	if (ret == ERR_CODE(PASSED)) {
		for (idx = 0; idx < ARRAY_SIZE(args_test_err_case); idx++) {
			if (!strcmp(args_test_err_case[idx].string, tst_err)) {
				*error = args_test_err_case[idx].status;
				break;
			}
		}
	} else if (ret == ERR_CODE(VALUE_NOTFOUND)) {
		ret = ERR_CODE(PASSED);
	}

	return ret;
}

int util_compare_buffers(unsigned char *buffer, unsigned int buffer_len,
			 unsigned char *expected_buffer,
			 unsigned int expected_len)
{
	if (buffer_len != expected_len) {
		DBG_PRINT("Bad length, got %d expected %d", buffer_len,
			  expected_len);
		return ERR_CODE(SUBSYSTEM);
	}

	if (buffer && expected_buffer &&
	    memcmp(buffer, expected_buffer, buffer_len)) {
		DBG_DHEX("Got buffer", buffer, buffer_len);
		DBG_DHEX("Expected buffer", expected_buffer, expected_len);
		return ERR_CODE(SUBSYSTEM);
	}

	return ERR_CODE(PASSED);
};

static const unsigned int t_data_2_json_type[] = {
	[t_boolean] = BIT(json_type_boolean),
	[t_int] = BIT(json_type_int),
	[t_string] = BIT(json_type_string),
	[t_object] = BIT(json_type_object),
	[t_buffer] = BIT(json_type_int) | BIT(json_type_string) |
		     BIT(json_type_array),
	[t_buffer_hex] = BIT(json_type_int) | BIT(json_type_string) |
			 BIT(json_type_array),
	[t_int64] = BIT(json_type_int),
	[t_double] = BIT(json_type_double),
	[t_sem] = BIT(json_type_string) | BIT(json_type_array),
};

int util_read_json_type(void *value, const char *key, enum t_data_type type,
			json_object *params)
{
	int ret = ERR_CODE(BAD_PARAM_TYPE);
	struct tbuffer *buf;

	json_type val_type;
	json_object *obj = NULL;

	if (!params || !key) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (type >= ARRAY_SIZE(t_data_2_json_type)) {
		DBG_PRINT("Parameter %s type \"%d\" not supported", key, type);
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	if (!json_object_object_get_ex(params, key, &obj)) {
		DBG_PRINT_VALUE_NOTFOUND(key);
		return ERR_CODE(VALUE_NOTFOUND);
	}

	val_type = json_object_get_type(obj);

	if (!(BIT(val_type) & t_data_2_json_type[type])) {
		DBG_PRINT_BAD_PARAM(key);
		return ERR_CODE(BAD_PARAM_TYPE);
	}

	if (value) {
		switch (type) {
		case t_boolean:
			*((bool *)value) = json_object_get_boolean(obj);
			ret = ERR_CODE(PASSED);
			break;

		case t_int:
			*((int *)value) = json_object_get_int(obj);
			ret = ERR_CODE(PASSED);
			break;

		case t_string:
			*((const char **)value) = json_object_get_string(obj);
			ret = ERR_CODE(PASSED);
			break;

		case t_buffer_hex:
			buf = value;
			buf->data = NULL;
			buf->length = 0;
			ret = util_read_hex_buffer(&buf->data, &buf->length,
						   params, key);
			break;

		case t_object:
		case t_sem:
		case t_buffer:
			*((json_object **)value) = obj;
			ret = ERR_CODE(PASSED);
			break;

		case t_int64:
			*((int64_t *)value) = json_object_get_int64(obj);
			ret = ERR_CODE(PASSED);
			break;

		case t_double:
			*((double *)value) = json_object_get_double(obj);
			ret = ERR_CODE(PASSED);
			break;

		default:
			ret = ERR_CODE(BAD_PARAM_TYPE);
			break;
		}
	} else {
		ret = ERR_CODE(PASSED);
	}

	return ret;
}

int util_read_json_file(char *dir, char *name, json_object **json_obj)
{
	int res = ERR_CODE(BAD_ARGS);
	char *definition_buffer = NULL;

	if (!name || !json_obj) {
		DBG_PRINT_BAD_ARGS();
		return res;
	}

	res = util_file_to_buffer(dir, name, &definition_buffer);
	if (res == ERR_CODE(PASSED)) {
		*json_obj = json_tokener_parse(definition_buffer);
		if (!*json_obj) {
			DBG_PRINT("Can't parse json definition buffer");
			res = ERR_CODE(INTERNAL);
		}
	} else {
		DBG_PRINT("Copy file into buffer failed");
	}

	if (definition_buffer)
		free(definition_buffer);

	return res;
}

int check_file_extension(char *filename, char *extension)
{
	char *file_extension = NULL;

	if (!filename || !extension)
		return ERR_CODE(BAD_ARGS);

	file_extension = strrchr(filename, '.');
	if (file_extension) {
		if (strcmp(file_extension, extension)) {
			DBG_PRINT("%s: Expected %s file extension", filename,
				  extension);
			return ERR_CODE(FAILED);
		} else {
			return ERR_CODE(PASSED);
		}
	}

	DBG_PRINT("strrchr returned NULL pointer");
	return ERR_CODE(INTERNAL);
}

char *util_get_strerr(void)
{
	if (__errno_location())
		return strerror(errno);

	return "Unknown error";
}

const char *util_get_err_code_str(int err)
{
	size_t idx;

	/* Find the error entry in the array of error string */
	for (idx = 0; idx < MAX_TEST_ERROR; idx++)
		if (err == ERR_CODE(idx))
			return list_err[idx].status;

	return list_err[INTERNAL].status;
}

__weak void util_dbg_printf(const char *function, int line, const char *fmt,
			    ...)
{
	(void)function;
	(void)line;
	(void)fmt;
}

__weak void util_dbg_dumphex(const char *function, int line, char *msg,
			     void *buf, size_t len)
{
	(void)function;
	(void)line;
	(void)msg;
	(void)buf;
	(void)len;
}

int util_get_json_obj_ids(const char *name, const char *key,
			  unsigned int *first, unsigned int *last)
{
	int err = ERR_CODE(INTERNAL);
	static const char delim[2] = ":";
	long val;
	char *tmp = NULL;
	char *field = NULL;

	if (!name || !first || !last)
		return ERR_CODE(BAD_ARGS);

	tmp = malloc(strlen(name) - strlen(key) + 1);
	if (!tmp) {
		DBG_PRINT_ALLOC_FAILURE();
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strcpy(tmp, name + strlen(key));

	/* Get the first thread id */
	field = strtok(tmp, delim);
	if (!field) {
		DBG_PRINT("Missing %s ID in %s", key, name);
		goto exit;
	}

	val = strtol(field, NULL, 10);
	if (!val) {
		DBG_PRINT("%s ID not valid in %s", key, name);
		goto exit;
	}

	*first = *last = val;

	/* Get the last thread id if any */
	field = strtok(NULL, delim);
	if (field) {
		val = strtol(field, NULL, 10);
		if (!val) {
			DBG_PRINT("%s ID not valid in %s", key, name);
			goto exit;
		}

		*last = val;
	}

	if (*last < *first) {
		DBG_PRINT("Wrong %s ID (%s) first = %u > last %u", key, name,
			  *first, *last);
		err = ERR_CODE(FAILED);
	}

	err = ERR_CODE(PASSED);

exit:
	free(tmp);

	return err;
}

int util_get_subdef(struct json_object **subdef, struct json_object *topdef,
		    struct test_data *test)
{
	int res;
	char *def_file = NULL;

	if (!subdef || !topdef || !test)
		return ERR_CODE(BAD_ARGS);

	/*
	 * Check if the top definition object is defined with a test
	 * definition file or a detailled json_object definition.
	 */
	res = util_read_json_type(&def_file, FILEPATH_OBJ, t_string, topdef);
	if (res == ERR_CODE(PASSED)) {
		/* Read the file definition */
		res = util_read_json_file(test->dir_def_file, def_file, subdef);
	} else if (res == ERR_CODE(VALUE_NOTFOUND)) {
		/*
		 * Increment reference to the top test definition
		 * in order to align with the file definition
		 * and call json_object_put() regardless how top definition
		 * test is defined.
		 */
		*subdef = json_object_get(topdef);
		res = ERR_CODE(PASSED);
	}

	if (res != ERR_CODE(PASSED))
		DBG_PRINT("Error %d", res);

	return res;
}
