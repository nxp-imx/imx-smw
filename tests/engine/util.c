// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "types.h"
#include "json_types.h"
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
struct smw_status {
	int status;
	char *string;
} status_codes[] = { SET_STATUS_CODE(SMW_STATUS_OK),
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
		     SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_FAILURE),
		     SET_STATUS_CODE(SMW_STATUS_SUBSYSTEM_NOT_CONFIGURED),
		     SET_STATUS_CODE(SMW_STATUS_OPERATION_NOT_SUPPORTED),
		     SET_STATUS_CODE(SMW_STATUS_OPERATION_NOT_CONFIGURED),
		     SET_STATUS_CODE(SMW_STATUS_OPERATION_FAILURE) };

/**
 * struct - test_err_case
 * @status: Integer value of 'test_error' json parameter.
 * @string: String value of 'test_error' json parameter presents in test
 *          definition file.
 */
struct test_err_case {
	enum arguments_test_err_case status;
	char *string;
} args_test_err_case[] = { SET_STATUS_CODE(ARGS_NULL),
			   SET_STATUS_CODE(KEY_DESC_NULL),
			   SET_STATUS_CODE(KEY_TYPE_UNDEFINED),
			   SET_STATUS_CODE(BAD_KEY_SEC_SIZE),
			   SET_STATUS_CODE(BAD_KEY_TYPE),
			   SET_STATUS_CODE(KEY_DESC_ID_SET),
			   SET_STATUS_CODE(PUB_KEY_BUFF_TOO_SMALL),
			   SET_STATUS_CODE(PRIV_KEY_BUFF_SET),
			   SET_STATUS_CODE(PRIV_KEY_BUFF_LEN_SET),
			   SET_STATUS_CODE(KEY_BUFFER_NULL),
			   SET_STATUS_CODE(PUB_DATA_LEN_NOT_SET),
			   SET_STATUS_CODE(PRIV_DATA_LEN_NOT_SET),
			   SET_STATUS_CODE(BAD_FORMAT),
			   SET_STATUS_CODE(WRONG_TYPE_NAME),
			   SET_STATUS_CODE(WRONG_SECURITY_SIZE),
			   SET_STATUS_CODE(KEY_DESC_ID_NOT_SET),
			   SET_STATUS_CODE(NO_BUFFER_SET),
			   SET_STATUS_CODE(BAD_VERSION),
			   SET_STATUS_CODE(BAD_ATTRIBUTES),
			   SET_STATUS_CODE(NB_ERROR_CASE) };

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
	SET_ERR_CODE_AND_NAME(BAD_PARAM_TYPE, "BAD PARAMETER TYPE")
};

#undef SET_ERR_CODE_AND_NAME

unsigned int list_err_size = ARRAY_SIZE(list_err);

int copy_file_into_buffer(char *filename, char **buffer)
{
	int res = ERR_CODE(INTERNAL);
	unsigned int size = 0;
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

	if (size != fread(*buffer, sizeof(char), size, f)) {
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

char *get_smw_string_status(unsigned int status)
{
	int i = 0;

	for (; i < ARRAY_SIZE(status_codes); i++) {
		if (status_codes[i].status == status)
			return status_codes[i].string;
	}

	return NULL;
}

int key_identifier_add_list(struct key_identifier_list **key_identifiers,
			    struct key_identifier_node *node)
{
	struct key_identifier_node *head = NULL;

	if (!node) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	if (!*key_identifiers) {
		*key_identifiers = malloc(sizeof(struct key_identifier_list));
		if (!*key_identifiers) {
			DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}

		/* New key is the first of the list */
		(*key_identifiers)->head = node;
	} else {
		head = (*key_identifiers)->head;
		while (head->next)
			head = head->next;

		/* New key is the last of the list */
		head->next = node;
	}

	return ERR_CODE(PASSED);
}

unsigned long long
find_key_identifier(struct key_identifier_list *key_identifiers,
		    unsigned int id)
{
	struct key_identifier_node *head = NULL;

	if (!key_identifiers) {
		DBG_PRINT_BAD_ARGS(__func__);
		return 0;
	}

	head = key_identifiers->head;

	while (head) {
		if (head->id == id)
			return head->key_identifier;

		head = head->next;
	}

	return 0;
}

void key_identifier_clear_list(struct key_identifier_list *key_identifiers)
{
	struct key_identifier_node *head = NULL;
	struct key_identifier_node *del = NULL;

	if (!key_identifiers)
		return;

	head = key_identifiers->head;

	while (head) {
		del = head;
		head = head->next;
		free(del);
	}

	free(key_identifiers);
}

int convert_string_to_hex(char *string, unsigned char **hex, unsigned int *len)
{
	char tmp[2] = { 0 };
	char *endptr = NULL;
	int i = 0;
	int j = 0;
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
		(*hex)[j] = strtol(tmp, &endptr, 16);
	}

	return ERR_CODE(PASSED);
}

int get_test_name(char **test_name, char *test_definition_file)
{
	int res = ERR_CODE(BAD_ARGS);
	unsigned int len = 0;
	char *file_extension = NULL;

	if (!test_name || !test_definition_file) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	/* First check test definition file extension */
	file_extension = strrchr(test_definition_file, '.');
	if (file_extension) {
		res = strcmp(file_extension, DEFINITION_FILE_EXTENSION);
		if (res) {
			DBG_PRINT("%s must be a JSON file",
				  test_definition_file);
			return ERR_CODE(BAD_ARGS);
		}
	} else {
		DBG_PRINT("strrchr returned NULL pointer");
		return ERR_CODE(INTERNAL);
	}

	/* Get filename from test definition file */
	len = file_extension - strrchr(test_definition_file, '/') - 1;

	*test_name = malloc(len);
	if (!*test_name) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	strncpy(*test_name, strrchr(test_definition_file, '/') + 1, len);

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
