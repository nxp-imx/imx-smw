/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <limits.h>
#include <stdio.h>
#include <json_object.h>

#include "json_types.h"
#include "types.h"

#include "smw_keymgr.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#ifndef BIT
#define BIT(n) (1 << (n))
#endif /* BIT */

#define UCHAR_SHIFT_BYTE(val, byte) ((val) >> ((byte) * (CHAR_BIT)) & UCHAR_MAX)

#ifndef BITS_TO_BYTES_SIZE
#define BITS_TO_BYTES_SIZE(nb_bits) (((nb_bits) + 7) / 8)
#endif

/*
 * Read a JSON-C name/value from an object containing field @f of
 * the structure @st
 */
#define UTIL_READ_JSON_ST_FIELD(st, f, type, jobj)                             \
	({                                                                     \
		int _ret;                                                      \
		do {                                                           \
			__typeof__(st) _st = st;                               \
			unsigned char *_elm = (unsigned char *)(_st);          \
			_elm += offsetof(__typeof__(*_st), f);                 \
			_ret = util_read_json_type(_elm, #f, t_##type, jobj);  \
		} while (0);                                                   \
		_ret;                                                          \
	})

/* File extension used */
#define DEFINITION_FILE_EXTENSION ".json"
#define TEST_STATUS_EXTENSION	  ".txt"

/* Test type specified by the definition file name */
#define TEST_API_TYPE "_API_"

#define ERR_CODE(val)	(list_err[(val)].code)
#define ERR_STATUS(val) (list_err[(val)].status)

#define FPRINT_SUBTEST_STATUS(file, subtest, status, error)                    \
	do {                                                                   \
		__typeof__(file) _f = (file);                                  \
		__typeof__(error) _err = (error);                              \
		(void)fprintf(_f, "%s: %s", subtest, status);                  \
		if (_err)                                                      \
			(void)fprintf(_f, " (%s)\n", _err);                    \
		else                                                           \
			(void)fprintf(_f, "\n");                               \
	} while (0)

#define FPRINT_TEST_INTERNAL_FAILURE(file, test_name)                          \
	(void)fprintf(file, "%s: %s (%s)\n", test_name, ERR_STATUS(FAILED),    \
		      ERR_STATUS(INTERNAL))

#define FPRINT_TEST_STATUS(file, test_name, status)                            \
	(void)fprintf(file, "%s: %s\n", (test_name), (status))

#define FPRINT_MESSAGE(file, ...) ((void)fprintf(file, __VA_ARGS__))

#if defined(ENABLE_TRACE)

#define DBG_PRINT_ALLOC_FAILURE(function, line)                                \
	printf("%s (%d): Memory allocation failed\n", function, line)

#define DBG_PRINT_BAD_ARGS(function) printf("%s: Bad arguments\n", function)

#define DBG_PRINT_BAD_PARAM(function, param)                                   \
	printf("%s: '%s' parameter isn't properly set\n", function, param)

#define DBG_PRINT_VALUE_NOTFOUND(param)                                        \
	printf("%s: '%s' value not found\n", __func__, param)

#define DBG_PRINT_MISS_PARAM(function, param)                                  \
	printf("%s: '%s' mandatory parameter is missing\n", function, param)

#define DBG_PRINT(...)                                                         \
	do {                                                                   \
		printf("%s: ", __func__);                                      \
		printf(__VA_ARGS__);                                           \
		printf("\n");                                                  \
	} while (0)

void dbg_dumphex(const char *function, int line, char *msg, void *buf,
		 size_t len);
#define DBG_DHEX(msg, buf, len) dbg_dumphex(__func__, __LINE__, msg, buf, len)

#else /* ENABLE_TRACE */

#define DBG_PRINT_ALLOC_FAILURE(function, line)
#define DBG_PRINT_BAD_ARGS(function)
#define DBG_PRINT_BAD_PARAM(function, param)
#define DBG_PRINT_VALUE_NOTFOUND(param)
#define DBG_PRINT_MISS_PARAM(function, param)
#define DBG_PRINT(...)
#define DBG_DHEX(msg, buf, len)

#endif /* ENABLE_TRACE */

/**
 * util_get_strerr() - Get the system error message
 *
 * If the system "errno" is defined get the current error message
 *
 * Return:
 * System error message
 * Otherwise unknown error message
 */
char *util_get_strerr(void);

#define ENUM_TO_STRING(name)                                                   \
	{                                                                      \
		.status = name, .string = #name                                \
	}

/* Compare @got and @exp. Return 0 if equal, 1 otherwise */
#define CHECK_RESULT(got, exp)                                                 \
	({                                                                     \
		int __ret = 0;                                                 \
		enum smw_status_code got_res = got;                            \
		enum smw_status_code exp_res = exp;                            \
		do {                                                           \
			if (got_res != exp_res) {                              \
				DBG_PRINT("Expected result is %s, got %s",     \
					  get_smw_string_status(exp_res),      \
					  get_smw_string_status(got_res));     \
				__ret = 1;                                     \
			}                                                      \
			break;                                                 \
		} while (0);                                                   \
		__ret;                                                         \
	})

/**
 * struct app_data - Application data structure
 * @dir_def_file:    Folder of the test definition file
 * @key_identifiers: Key identifiers list
 * @op_contexts:     Operation context list
 * @threads:         Application threads list
 * @semaphores:      Semaphores list
 * @log:             Application log file
 * @is_multithread:  Application is multithread
 * @is_api_test:     Flag if test only SMW's API
 * @definition:      Application test definition
 */
struct app_data {
	char *dir_def_file;
	struct llist *key_identifiers;
	struct llist *op_contexts;
	struct llist *threads;
	struct llist *semaphores;
	FILE *log;
	int is_multithread;
	int is_api_test;
	struct json_object *definition;
};

/**
 * util_setup_app() - Setup the application global data
 *
 * Return:
 * Pointer to the application data object
 * Otherwise NULL if error
 */
struct app_data *util_setup_app(void);

/**
 * util_get_app() - Get the application global data
 *
 * Return:
 * Pointer to the application data object
 */
struct app_data *util_get_app(void);

/**
 * util_destroy_app() - Destroy the application global data
 */
void util_destroy_app(void);

/**
 * get_smw_int_status() - Convert SMW status string value into integer value.
 * @smw_status: Pointer to integer smw status to update. Not updated if an error
 *              is returned.
 * @string: SMW status string.
 *
 * Return:
 * PASSED		- Success.
 * -UNKNOWN_RESULT	- @string is not present in status codes array.
 * -BAD_ARGS		- One of the argument is bad.
 */
int get_smw_int_status(int *smw_status, const char *string);

/**
 * get_smw_string_status() - Convert SMW status integer value into string value.
 * @status: SMW status integer.
 *
 * Return:
 * NULL	- Status doesn't exist.
 * SMW status string value otherwise.
 */
char *get_smw_string_status(enum smw_status_code status);

/**
 * get_test_name() - Get test name from test definition file.
 * @test_name: Pointer to test name buffer. Allocated by this function and must
 *             be freed by caller.
 * @test_definition_file: Pointer to test definition file.
 *
 * Before getting the test name, this function checks that the test definition
 * file has a good file extension (.json).
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL			- strrchr() failed.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int get_test_name(char **test_name, char *test_definition_file);

/**
 * get_test_err_status() - Get 'test_error' integer value from string value.
 * @status: Pointer to integer 'test_error' parameter status to update.
 *          Not updated if an error is returned.
 * @string: 'test_error' status string.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_PARAM_TYPE	- @string is not present in args test err case array.
 * -BAD_ARGS		- One of the argument is bad.
 */
int get_test_err_status(unsigned int *status, const char *string);

/**
 * util_string_to_hex() - Convert ASCII string to hex string.
 * @string: Input string.
 * @hex: Hex output string. Allocated by the function. Must be freed by the
 *       caller.
 * @len: Pointer to @hex length in bytes. Not updated if function failed.
 *
 * This function convert an ASCII string that represents hexadecimal values
 * to hex string.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int util_string_to_hex(char *string, unsigned char **hex, unsigned int *len);

/**
 * util_read_json_buffer() - Read a data buffer from json-c object
 * @buf: Buffer read
 * @buf_len: Length of the buffer read
 * @json_len: Length set in json-c object buffer definition
 * @obuf: Json_c buffer object to read
 *
 * Function allocates the output buffer @buf and reads json-c buffer
 * object.
 * Buffer can be defined with one entry or an array of entries.
 * If the definition of the buffer is an integer or if the first entry
 * of the array is an integer, it's the buffer length in bytes regardless
 * of the define buffer data (data is defined by string or multiple strings).
 *
 * Buffer formatting can be:
 * - "buffer": x
 * - "buffer": [x, "hex string 0", "hex string 1", ...]
 * - "buffer": ["hex string 0", "hex string 1", ...]
 * - "buffer": "hex string"
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int util_read_json_buffer(char **buf, unsigned int *buf_len,
			  unsigned int *json_len, json_object *obuf);

/**
 * util_read_hex_buffers() - Read an hexadecimal buffer definition
 * @hex: Hexadecimal data buffer.
 * @length: Length of the data buffer.
 * @params: json-c object
 * @field: Field key name to get in json-c @param object
 *
 * Call function util_read_json_buffer() to read json-c buffer as defined
 * by util_read_json_buffer() function.
 * If test definition contains data in string format, converts it to
 * hexadecimal buffer value.
 * The output @hex buffer is allocated by this function but must be freed
 * by caller if function succeed.
 * The output @length value might not reflect the real length of the @hex
 * buffer.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -MISSING_PARAMS          - Params' field not defined
 * -FAILED                  - Error in definition file
 */
int util_read_hex_buffer(unsigned char **hex, unsigned int *length,
			 json_object *params, const char *field);

/**
 * util_read_test_error() - Get the test error type if defined
 * @error: Test error type
 * @params: json-c parameters
 *
 * Return the 'test_error' parameter if specified in the test
 * definition.
 * Else @error is 'NOT_DEFINED'
 *
 * Return:
 * PASSED           - Success.
 * -BAD_PARAM_TYPE  - Test error is not suuported.
 * -BAD_ARGS        - One of the argument is bad.
 */
int util_read_test_error(enum arguments_test_err_case *error,
			 json_object *params);

/**
 * util_compare_buffers() - Compare two buffers
 * @buffer: Buffer to compare
 * @buffer_len: @buffer length in bytes
 * @expected_buffer: Expected buffer
 * @expected_len: @expected_buffer length in bytes
 *
 * If @buffer or @expected_buffer is not set, only @buffer_len and @expected_len
 * are compared.
 *
 * Return:
 * PASSED	- Success
 * -SUBSYSTEM	- @buffer and @expected_buffer are different
 */
int util_compare_buffers(unsigned char *buffer, unsigned int buffer_len,
			 unsigned char *expected_buffer,
			 unsigned int expected_len);
/**
 * util_read_json_type() - Read an json-c @key value of type @type
 * @value: Pointer to the output value read (can be NULL)
 * @key: Key value to read
 * @type: data type to read
 * @params: json-c object where is the @key value
 *
 * Searches if the @key value is defined in json-c @params.
 * Then if @key found, verifies if the @key value type is supported and
 * correctly defined json-c object.
 * Finally if the type is correct and the @value is not NULL, reads the
 * value.
 *
 * If @value is NULL, functions is used to find and check if @key exists
 * and its type is same as @type.
 *
 * Return:
 * PASSED           - Success.
 * -BAD_PARAM_TYPE  - Parameter type is not correct or not supported.
 * -BAD_ARGS        - One of the argument is bad.
 * -VALUE_NOTFOUND  - Value not found.
 * -FAILED          - Error in definition file
 */
int util_read_json_type(void *value, const char *key, enum t_data_type type,
			json_object *params);

/**
 * util_read_json_file() - Fill a json object with file content.
 * @dir: Directory where is the file (can be NULL).
 * @name: Name of the file.
 * @json_obj: Pointer to json_obj. Not updated if an error is returned.
 *
 * This function copies @file_path content into a buffer and then fills
 * the json object with the buffer content.
 *
 * Return:
 * PASSED	- Success.
 * -BAD_ARGS	- One of the arguments is bad.
 * -INTERNAL	- json_tokener_parse() failed.
 * Error code from copy_file_into_buffer().
 */
int util_read_json_file(char *dir, char *name, json_object **json_obj);

/**
 * check_file_extension() - Check a filename extension.
 * @filename: Filename.
 * @extension: Expected file extension.
 *
 * Return:
 * PASSED- Success.
 * -BAD_ARGS	- One of the argument is invalid.
 * -INTERNAL	- Internal function failure.
 * -FAILED	- @extension doesn't match @filename extension.
 */
int check_file_extension(char *filename, char *extension);

#endif /* __UTIL_H__ */
