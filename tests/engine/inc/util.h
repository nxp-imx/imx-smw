/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
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

#define UCHAR_SHIFT_BYTE(val, byte) ((val) >> ((byte) * (CHAR_BIT)) & UCHAR_MAX)

#ifndef BITS_TO_BYTES_SIZE
#define BITS_TO_BYTES_SIZE(nb_bits) (((nb_bits) + 7) / 8)
#endif

/* File extension used */
#define DEFINITION_FILE_EXTENSION ".json"
#define TEST_STATUS_EXTENSION	  ".txt"

/* Test type specified by the definition file name */
#define TEST_API_TYPE "_API_"

#define ERR_CODE(val)	(list_err[(val)].code)
#define ERR_STATUS(val) (list_err[(val)].status)

#define FPRINT_SUBTEST_STATUS(file, subtest, status, error_code)               \
	do {                                                                   \
		__typeof__(file) f = (file);                                   \
		__typeof__(error_code) error = (error_code);                   \
		fprintf(f, "%s: %s", subtest, status);                         \
		if (error)                                                     \
			fprintf(f, " (%s)\n", error);                          \
		else                                                           \
			fprintf(f, "\n");                                      \
	} while (0)

#define FPRINT_TEST_INTERNAL_FAILURE(file, test_name)                          \
	fprintf(file, "%s: %s (%s)\n", test_name, ERR_STATUS(FAILED),          \
		ERR_STATUS(INTERNAL))

#define FPRINT_TEST_STATUS(file, test_name, status)                            \
	fprintf(file, "%s: %s\n", (test_name), (status))

#define FPRINT_MESSAGE(file, ...) fprintf(file, __VA_ARGS__)

#if defined(ENABLE_TRACE)

#define DBG_PRINT_ALLOC_FAILURE(function, line)                                \
	printf("%s (%d): Memory allocation failed\n", function, line)

#define DBG_PRINT_BAD_ARGS(function) printf("%s: Bad arguments\n", function)

#define DBG_PRINT_BAD_PARAM(function, param)                                   \
	printf("%s: '%s' parameter isn't properly set\n", function, param)

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
#define DBG_PRINT_MISS_PARAM(function, param)
#define DBG_PRINT(...)
#define DBG_DHEX(msg, buf, len)

#endif /* ENABLE_TRACE */

/* Compare @got and @exp. Return 0 if equal, 1 otherwise */
#define CHECK_RESULT(got, exp)                                                 \
	({                                                                     \
		int __ret = 0;                                                 \
		int got_res = got;                                             \
		int exp_res = exp;                                             \
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
 * copy_file_into_buffer() - Copy file content into buffer.
 * @filename: Name of the file to copy.
 * @buffer: Pointer to buffer to fill. Allocate by this function and must be
 *          free by caller.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL			- Internal error.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS- One of the arguments is bad.
 */
int copy_file_into_buffer(char *filename, char **buffer);

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
char *get_smw_string_status(unsigned int status);

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

#endif /* __UTIL_H__ */
