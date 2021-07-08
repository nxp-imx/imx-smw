// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <libgen.h>
#include <stdlib.h>
#include <string.h>

#include "json_util.h"
#include "util.h"
#include "json.h"
#include "smw_keymgr.h"
#include "smw_status.h"

#define SET_STATUS_CODE(name)                                                  \
	{                                                                      \
		.status = name, .string = #name                                \
	}

/**
 * struct - smw status
 * @status: smw status integer value.
 * @string: smw status string value.
 */
static const struct smw_status {
	enum smw_status_code status;
	char *string;
} status_codes[] = {
	SET_STATUS_CODE(SMW_STATUS_OK),
	SET_STATUS_CODE(SMW_STATUS_INVALID_VERSION),
	SET_STATUS_CODE(SMW_STATUS_INVALID_BUFFER),
	SET_STATUS_CODE(SMW_STATUS_EOF),
	SET_STATUS_CODE(SMW_STATUS_SYNTAX_ERROR),
	SET_STATUS_CODE(SMW_STATUS_UNKNOWN_NAME),
	SET_STATUS_CODE(SMW_STATUS_UNKNOWN_ID),
	SET_STATUS_CODE(SMW_STATUS_TOO_LARGE_NUMBER),
	SET_STATUS_CODE(SMW_STATUS_ALLOC_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_INVALID_PARAM),
	SET_STATUS_CODE(SMW_STATUS_VERSION_NOT_SUPPORTED),
	SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_LOAD_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_UNLOAD_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED),
	SET_STATUS_CODE(SMW_STATUS_OPERATION_NOT_SUPPORTED),
	SET_STATUS_CODE(SMW_STATUS_OPERATION_NOT_CONFIGURED),
	SET_STATUS_CODE(SMW_STATUS_OPERATION_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_SIGNATURE_INVALID),
	SET_STATUS_CODE(SMW_STATUS_NO_KEY_BUFFER),
	SET_STATUS_CODE(SMW_STATUS_OUTPUT_TOO_SHORT),
	SET_STATUS_CODE(SMW_STATUS_SIGNATURE_LEN_INVALID),
	SET_STATUS_CODE(SMW_STATUS_OPS_INVALID),
	SET_STATUS_CODE(SMW_STATUS_MUTEX_INIT_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_MUTEX_DESTROY_FAILURE),
	SET_STATUS_CODE(SMW_STATUS_INVALID_TAG),
	SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_DUPLICATE),
	SET_STATUS_CODE(SMW_STATUS_OPERATION_DUPLICATE),
	SET_STATUS_CODE(SMW_STATUS_CONFIG_ALREADY_LOADED),
	SET_STATUS_CODE(SMW_STATUS_NO_CONFIG_LOADED),
};

/**
 * struct - test_err_case
 * @status: Integer value of 'test_error' json parameter.
 * @string: String value of 'test_error' json parameter presents in test
 *          definition file.
 */
struct test_err_case {
	enum arguments_test_err_case status;
	char *string;
} args_test_err_case[] = {
	SET_STATUS_CODE(ARGS_NULL),
	SET_STATUS_CODE(BAD_FORMAT),
	SET_STATUS_CODE(KEY_BUFFER_NULL),
	SET_STATUS_CODE(KEY_DESC_ID_NOT_SET),
	SET_STATUS_CODE(KEY_DESC_ID_SET),
	SET_STATUS_CODE(KEY_DESC_NULL),
	SET_STATUS_CODE(KEY_DESC_OUT_NULL),
	SET_STATUS_CODE(NB_ERROR_CASE),
	SET_STATUS_CODE(CIPHER_NO_NB_KEYS),
	SET_STATUS_CODE(CIPHER_NO_KEYS),
	SET_STATUS_CODE(CIPHER_DIFF_SUBSYSTEM),
	SET_STATUS_CODE(CIPHER_DIFF_KEY_TYPE),
	SET_STATUS_CODE(CTX_NULL),
	SET_STATUS_CODE(CTX_HANDLE_NULL),
	SET_STATUS_CODE(DST_CPY_ARGS_NULL),
	SET_STATUS_CODE(TLS12_KDF_ARGS_NULL),
	SET_STATUS_CODE(FAKE_KEY_ID),
};
#undef SET_STATUS_CODE

#define SET_ERR_CODE_AND_NAME(err, name)                                       \
	{                                                                      \
		.code = -(err), .status = name                                 \
	}

const struct error list_err[] = {
	SET_ERR_CODE_AND_NAME(PASSED, "PASSED"),
	SET_ERR_CODE_AND_NAME(FAILED, "FAILED"),
	SET_ERR_CODE_AND_NAME(INTERNAL, "INTERNAL"),
	SET_ERR_CODE_AND_NAME(INTERNAL_OUT_OF_MEMORY, "INTERNAL OUT OF MEMORY"),
	SET_ERR_CODE_AND_NAME(UNDEFINED_CMD, "UNDEFINED COMMAND"),
	SET_ERR_CODE_AND_NAME(MISSING_PARAMS, "MISSING MANDATORY PARAMS"),
	SET_ERR_CODE_AND_NAME(UNKNOWN_RESULT, "UNKNOWN RESULT"),
	SET_ERR_CODE_AND_NAME(BAD_RESULT, "BAD RESULT"),
	SET_ERR_CODE_AND_NAME(BAD_ARGS, "BAD ARGUMENTS"),
	SET_ERR_CODE_AND_NAME(SUBSYSTEM, "SUBSYSTEM ERROR"),
	SET_ERR_CODE_AND_NAME(NOT_RUN, "NOT RUN"),
	SET_ERR_CODE_AND_NAME(BAD_PARAM_TYPE, "BAD PARAMETER TYPE"),
	SET_ERR_CODE_AND_NAME(VALUE_NOTFOUND, "VALUE NOT FOUND"),
	SET_ERR_CODE_AND_NAME(KEY_NOTFOUND, "KEY NOT FOUND"),
	SET_ERR_CODE_AND_NAME(ERROR_NOT_DEFINED, "TEST ERROR NOT DEFINED"),
};

#undef SET_ERR_CODE_AND_NAME

unsigned int list_err_size = ARRAY_SIZE(list_err);

int copy_file_into_buffer(char *filename, char **buffer)
{
	int res = ERR_CODE(INTERNAL);
	long size = 0;
	FILE *f = NULL;

	if (!filename || !buffer) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	f = fopen(filename, "r");
	if (!f) {
		DBG_PRINT("can't open file %s", filename);
		return res;
	}

	if (fseek(f, 0, SEEK_END)) {
		if (ferror(f))
			perror("fseek() SEEK_END");

		goto exit;
	}

	size = ftell(f);
	if (size == -1) {
		if (ferror(f))
			perror("ftell()");

		goto exit;
	}

	if (fseek(f, 0, SEEK_SET)) {
		if (ferror(f))
			perror("fseek() SEEK_SET");

		goto exit;
	}

	*buffer = malloc(size);
	if (!*buffer) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		res = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	if (size != (long)fread(*buffer, sizeof(char), size, f)) {
		if (feof(f))
			DBG_PRINT("Error reading %s: unexpected EOF", filename);
		else if (ferror(f))
			perror("fread()");

		goto exit;
	}

	res = ERR_CODE(PASSED);

exit:
	if (fclose(f))
		perror("fclose()");

	if (*buffer && res != ERR_CODE(PASSED))
		free(*buffer);

	return res;
}

int get_smw_int_status(int *smw_status, const char *string)
{
	unsigned int i = 0;

	if (!string || !smw_status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	for (; i < ARRAY_SIZE(status_codes); i++) {
		if (!strcmp(status_codes[i].string, string)) {
			*smw_status = status_codes[i].status;
			return ERR_CODE(PASSED);
		}
	}

	DBG_PRINT("Unknown expected result");
	return ERR_CODE(UNKNOWN_RESULT);
}

char *get_smw_string_status(enum smw_status_code status)
{
	unsigned long i = 0;

	for (; i < ARRAY_SIZE(status_codes); i++) {
		if (status_codes[i].status == status)
			return status_codes[i].string;
	}

	return NULL;
}

int util_string_to_hex(char *string, unsigned char **hex, unsigned int *len)
{
	char tmp[3] = { 0 };
	int i = 0;
	unsigned int j = 0;
	int string_len = 0;

	if (!string || !hex || !len) {
		DBG_PRINT_BAD_ARGS(__func__);
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
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
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
		DBG_PRINT_BAD_ARGS(__func__);
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
		DBG_PRINT_BAD_ARGS(__func__);
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
		DBG_PRINT_BAD_ARGS(__func__);
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
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strncpy(*test_name, filename, len);
	(*test_name)[len] = '\0';

	return ERR_CODE(PASSED);
}

int get_test_err_status(unsigned int *status, const char *string)
{
	unsigned int idx = 0;

	if (!string || !status) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	for (; idx < ARRAY_SIZE(args_test_err_case); idx++) {
		if (!strcmp(args_test_err_case[idx].string, string)) {
			*status = args_test_err_case[idx].status;
			return ERR_CODE(PASSED);
		}
	}

	DBG_PRINT_BAD_PARAM(__func__, "test_error");
	return ERR_CODE(BAD_PARAM_TYPE);
}

int util_read_test_error(enum arguments_test_err_case *error,
			 json_object *params)
{
	int ret = ERR_CODE(PASSED);
	json_object *obj = NULL;

	*error = NOT_DEFINED;

	if (json_object_object_get_ex(params, TEST_ERR_OBJ, &obj))
		ret = get_test_err_status(error, json_object_get_string(obj));

	return ret;
}

#ifdef ENABLE_TRACE
void dbg_dumphex(const char *function, int line, char *msg, void *buf,
		 size_t len)
{
	size_t idx;
	char out[256];
	int off = 0;

	printf("%s:%d %s (%p-%zu)\n", function, line, msg, buf, len);

	for (idx = 0; idx < len; idx++) {
		if (((idx % 16) == 0) && idx > 0) {
			printf("%s\n", out);
			off = 0;
		}
		off += snprintf(out + off, (sizeof(out) - off), "%02X ",
				((char *)buf)[idx]);
	}

	if (off > 0)
		printf("%s\n", out);

	(void)fflush(stdout);
}
#endif

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
};

int util_read_json_type(void *value, const char *key, enum t_data_type type,
			json_object *params)
{
	int ret = ERR_CODE(BAD_PARAM_TYPE);
	struct tbuffer *buf;

	json_type val_type;
	json_object *obj = NULL;

	if (!params || !key) {
		DBG_PRINT_BAD_ARGS(__func__);
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
		DBG_PRINT_BAD_PARAM(__func__, key);
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
			*((json_object **)value) = obj;
			ret = ERR_CODE(PASSED);
			break;

		case t_int64:
			*((int64_t *)value) = json_object_get_int64(obj);
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

int file_to_json_object(char *file_path, json_object **json_obj)
{
	int res = ERR_CODE(BAD_ARGS);
	char *definition_buffer = NULL;

	if (!file_path || !json_obj) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	res = copy_file_into_buffer(file_path, &definition_buffer);
	if (res != ERR_CODE(PASSED)) {
		DBG_PRINT("Copy file into buffer failed");
		return res;
	}

	*json_obj = json_tokener_parse(definition_buffer);
	if (!*json_obj) {
		DBG_PRINT("Can't parse json definition buffer");
		res = ERR_CODE(INTERNAL);
	}

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
