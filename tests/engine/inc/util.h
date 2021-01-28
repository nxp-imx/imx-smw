/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <limits.h>
#include <stdio.h>
#include <json_object.h>

#include "smw_keymgr.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#define UCHAR_SHIFT_BYTE(val, byte) ((val) >> ((byte) * (CHAR_BIT)) & UCHAR_MAX)

/* File extension used */
#define DEFINITION_FILE_EXTENSION ".json"
#define TEST_STATUS_EXTENSION	  ".txt"

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

#define BASE64_FORMAT "BASE64"
#define HEX_FORMAT    "HEX"

/**
 * struct key_identifier_node - Node of key identifier linked list.
 * @id: Local ID of the key identifier. Comes from test definition file.
 * @key_identifier: Key identifier assigned by SMW.
 * @next: Pointer to next node.
 */
struct key_identifier_node {
	unsigned int id;
	unsigned long long key_identifier;
	struct key_identifier_node *next;
};

/**
 * struct key_identifier_list - Linked list to save keys identifiers.
 * @head: Pointer to the head of the linked list
 */
struct key_identifier_list {
	struct key_identifier_node *head;
};

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
 * key_identifier_add_list() - Add a new node in a key identifier linked list.
 * @key_identifiers: Pointer to linked list.
 * @node: Linked list node.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- @node is NULL.
 */
int key_identifier_add_list(struct key_identifier_list **key_identifiers,
			    struct key_identifier_node *node);

/**
 * find_key_identifier() - Search a key identifier.
 * @key_identifiers: Key identifier linked list where the research is done.
 * @id: Id of the key identifier.
 *
 * Return:
 * 0	- @key_identifiers is NULL or @id is not found.
 * Key identifier otherwise.
 */
unsigned long long
find_key_identifier(struct key_identifier_list *key_identifiers,
		    unsigned int id);

/**
 * key_identifier_clear_list() - Clear key identifier linked list.
 * @key_identifiers: Key identifier linked list to clear.
 *
 * Return:
 * none
 */
void key_identifier_clear_list(struct key_identifier_list *key_identifiers);

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
 * util_read_keys() - Read the public and private key definition
 * @key: SMW Key buffer parameter to setup
 * @params: json-c object
 *
 * Read and set the key format, public key buffer and private key buffer.
 * Key buffer is defined by a string or an array of string.
 * The public and private data buffer of the @key SMW buffer object are
 * allocated by this function but must be freed by caller if function
 * succeed.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
int util_read_keys(struct smw_keypair_buffer *key, json_object *params);

/**
 * util_read_hex_buffers() - Read an hexadecimal buffer definition
 * @hex: Hex output buffer.
 * @len: Length of the buffer @hex in bytes.
 * @params: json-c object
 * @field: Field key name to get in json-c @param object
 *
 * Read a buffer defined by a string or an array of string and converts
 * it in hexadecimal buffer.
 * The output @hex buffer is allocated by this function but must be freed
 * by caller if function succeed.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -MISSING_PARAMS          - Params' field not defined
 * -FAILED                  - Error in definition file
 */
int util_read_hex_buffer(unsigned char **hex, unsigned int *len,
			 json_object *params, const char *field);

#endif /* __UTIL_H__ */
