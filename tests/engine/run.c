// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "types.h"
#include "keymgr.h"
#include "crypto.h"
#include "json_types.h"
#include "run.h"
#include "paths.h"
#include "smw_status.h"

/* Key identifiers linked list */
static struct key_identifier_list *key_identifiers;

/**
 * execute_generate_cmd() - Execute generate key command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from generate_key().
 */
static int execute_generate_cmd(char *cmd, struct json_object *params,
				struct common_parameters *common_params,
				struct key_identifier_list **key_ids,
				int *status)
{
	if (!strcmp(cmd, GENERATE))
		return generate_key(params, common_params, NULL, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_AES))
		return generate_key(params, common_params, AES_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_BR1))
		return generate_key(params, common_params, BR1_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_BT1))
		return generate_key(params, common_params, BT1_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_DES))
		return generate_key(params, common_params, DES_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_DES3))
		return generate_key(params, common_params, DES3_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_DSA_SM2))
		return generate_key(params, common_params, DSA_SM2_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_NIST))
		return generate_key(params, common_params, NIST_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_SM4))
		return generate_key(params, common_params, SM4_KEY, key_ids,
				    status);
	else if (!strcmp(cmd, GENERATE_UNDEFINED))
		return generate_key(params, common_params, UNDEFINED_KEY,
				    key_ids, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_hash_cmd() - Execute hash command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_hash_cmd(char *cmd, struct json_object *params,
			    struct common_parameters *common_params,
			    int *status)
{
	if (!strcmp(cmd, HASH_MD5))
		return hash(params, common_params, MD5_ALG, status);
	else if (!strcmp(cmd, HASH_SHA1))
		return hash(params, common_params, SHA1_ALG, status);
	else if (!strcmp(cmd, HASH_SHA224))
		return hash(params, common_params, SHA224_ALG, status);
	else if (!strcmp(cmd, HASH_SHA256))
		return hash(params, common_params, SHA256_ALG, status);
	else if (!strcmp(cmd, HASH_SHA384))
		return hash(params, common_params, SHA384_ALG, status);
	else if (!strcmp(cmd, HASH_SHA512))
		return hash(params, common_params, SHA512_ALG, status);
	else if (!strcmp(cmd, HASH_SM3))
		return hash(params, common_params, SM3_ALG, status);
	else if (!strcmp(cmd, HASH_UNDEFINED))
		return hash(params, common_params, UNDEFINED_ALG, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_command() - Execute a subtest command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Other error code otherwise.
 */
static int execute_command(char *cmd, struct json_object *params,
			   struct common_parameters *common_params,
			   struct key_identifier_list **key_ids, int *status)
{
	if (!strcmp(cmd, DELETE))
		return delete_key(params, common_params, *key_ids, status);
	else if (!strncmp(cmd, GENERATE, strlen(GENERATE)))
		return execute_generate_cmd(cmd, params, common_params, key_ids,
					    status);
	else if (!strncmp(cmd, HASH, strlen(HASH)))
		return execute_hash_cmd(cmd, params, common_params, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * update_status() - Update subtest status, subtest error code and test status.
 * @sub_res: Result of the subtest.
 * @sub_status: Subtest status to update (PASSED or FAILED).
 * @sub_err: Subtest error code to update.
 * @test_status: Test status to update.
 * @status: Subtest command status from SMW API.
 *
 * If a subtest failed, the test status becomes FAILED.
 * If the subtest result is not a specific error code, the subtest error
 * code is the SMW status returned by the SMW API. This case appears when
 * the subtest result is different from the expected one.
 *
 * Return:
 * PASSED	- Success.
 * -BAD_ARGS	- One of the arguments is bad.
 */
static int update_status(int sub_res, char **sub_status, const char **sub_err,
			 int *test_status, int status)
{
	int idx = 0;

	if (!test_status || !sub_status || !sub_err) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	if (!sub_res) {
		*sub_status = (char *)ERR_STATUS(PASSED);
	} else {
		if (!*test_status)
			*test_status = ERR_CODE(FAILED);

		*sub_status = (char *)ERR_STATUS(FAILED);

		for (; idx < list_err_size; idx++) {
			if (sub_res == ERR_CODE(idx)) {
				if (idx == BAD_RESULT)
					*sub_err =
						get_smw_string_status(status);
				else
					*sub_err = ERR_STATUS(idx);

				return ERR_CODE(PASSED);
			}
		}

		*sub_err = ERR_STATUS(INTERNAL);
	}

	return ERR_CODE(PASSED);
}

/**
 * run_subtest() - Run a subtest.
 * @obj_iter: Pointer to json object iterator of the json definition file
 *            object.
 * @status_file: Pointer to the test status file.
 * @test_status: Pointer to the test status variable.
 *
 * Return:
 * none.
 */
static void run_subtest(struct json_object_iter *obj_iter, FILE *status_file,
			int *test_status)
{
	int res = ERR_CODE(FAILED);
	int status = SMW_STATUS_OPERATION_FAILURE;
	int depends = 0;
	char depends_status[SUBTEST_STATUS_PASSED_MAX_LEN] = { 0 };
	char file_line[SUBTEST_STATUS_PASSED_MAX_LEN] = { 0 };
	char *command_name = NULL;
	char *expected_status = NULL;
	char *sub_status = NULL;
	const char *sub_error = NULL;
	struct common_parameters common_params = { 0 };
	fpos_t status_file_pos = { 0 };
	json_object *cmd_obj = NULL;
	json_object *depends_obj = NULL;
	json_object *res_obj = NULL;
	json_object *sub_obj = NULL;
	json_object *version_obj = NULL;

	if (!obj_iter || !status_file || !test_status) {
		DBG_PRINT_BAD_ARGS(__func__);

		if (test_status)
			if (*test_status == ERR_CODE(PASSED))
				*test_status = ERR_CODE(FAILED);

		return;
	}

	/* Verify the presence of subtest json object */
	if (strncmp(obj_iter->key, SUBTEST_OBJ, SUBTEST_OBJ_LEN) ||
	    json_object_get_type(obj_iter->val) != json_type_object) {
		FPRINT_MESSAGE(status_file, "Error in test definiton file: ");
		FPRINT_MESSAGE(status_file, "subtest object is not present\n");
		DBG_PRINT("subtest object is not present");

		if (*test_status == ERR_CODE(PASSED))
			*test_status = ERR_CODE(FAILED);

		return;
	}

	/* 'command' is a mandatory parameter */
	if (!json_object_object_get_ex(obj_iter->val, CMD_OBJ, &cmd_obj)) {
		DBG_PRINT_MISS_PARAM(__func__, "command");
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	}

	command_name = (char *)json_object_get_string(cmd_obj);

	/*
	 * 'subsystem' is a mandatory parameter for all commands except
	 * 'DELETE'.
	 */
	if (strcmp(command_name, DELETE) &&
	    !json_object_object_get_ex(obj_iter->val, SUBSYSTEM_OBJ,
				       &sub_obj)) {
		res = ERR_CODE(MISSING_PARAMS);
		goto exit;
	} else {
		common_params.subsystem =
			(char *)json_object_get_string(sub_obj);
	}

	/*
	 * Get dependent subtest parameter 'depends' set in test definition
	 * file. If set, the subtest is run only if the dependent subtest status
	 * is PASSED.
	 */
	if (json_object_object_get_ex(obj_iter->val, DEPENDS_OBJ,
				      &depends_obj)) {
		depends = json_object_get_int(depends_obj);
		if (depends <= 0) {
			DBG_PRINT_BAD_PARAM(__func__, "depends");
			res = ERR_CODE(BAD_PARAM_TYPE);
			goto exit;
		}

		/* Expected dependent subtest status */
		sprintf(depends_status, "%s%d: PASSED\n", SUBTEST_OBJ, depends);

		/* Backup current status file position */
		fgetpos(status_file, &status_file_pos);

		/* Set status file position to beginning */
		rewind(status_file);

		depends = 0;
		while (fgets(file_line, SUBTEST_STATUS_PASSED_MAX_LEN,
			     status_file)) {
			if (!strcmp(file_line, depends_status)) {
				depends = 1;
				break;
			}
		}

		/* Restore status file position */
		fsetpos(status_file, &status_file_pos);

		if (!depends) {
			res = ERR_CODE(NOT_RUN);
			goto exit;
		}
	}

	/*
	 * Get expected result parameter 'result' set in test definition file.
	 * If not defined, the default value is SMW_STATUS_OK.
	 */
	if (json_object_object_get_ex(obj_iter->val, RES_OBJ, &res_obj)) {
		expected_status = (char *)json_object_get_string(res_obj);
		res = get_smw_int_status(&common_params.expected_res,
					 expected_status);

		if (res != ERR_CODE(PASSED))
			goto exit;

	} else {
		common_params.expected_res = SMW_STATUS_OK;
	}

	/*
	 * Get SMW API version.
	 * If not set in test definition file, use default value.
	 */
	if (json_object_object_get_ex(obj_iter->val, VERSION_OBJ, &version_obj))
		common_params.version = json_object_get_int(version_obj);
	else
		common_params.version = SMW_API_DEFAULT_VERSION;

	/* Execute subtest command */
	res = execute_command(command_name, obj_iter->val, &common_params,
			      &key_identifiers, &status);

exit:
	res = update_status(res, &sub_status, &sub_error, test_status, status);

	FPRINT_SUBTEST_STATUS(status_file, obj_iter->key, sub_status,
			      sub_error);
	FPRINT_SUBTEST_STATUS(stdout, obj_iter->key, sub_status, sub_error);
}

/**
 * file_to_json_object() - Fill a json object with file content.
 * @file_path: Path of the file.
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
static int file_to_json_object(char *file_path, json_object **json_obj)
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

int run_test(char *test_definition_file, char *test_name, char *output_dir)
{
	int res = ERR_CODE(FAILED);
	int test_status = ERR_CODE(PASSED);
	int file_path_size = 0;
	char *file_path = NULL;
	struct json_object_iter iter = { 0 };
	FILE *status_file = NULL;
	json_object *definition_obj = NULL;

	if (!test_definition_file || !test_name) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	file_path_size = strlen(test_name) + strlen(TEST_STATUS_EXTENSION) + 1;

	if (output_dir)
		file_path_size += strlen(output_dir) + 1;
	else
		file_path_size += strlen(DEFAULT_OUT_STATUS_PATH);

	file_path = malloc(file_path_size);
	if (!file_path) {
		DBG_PRINT_ALLOC_FAILURE(__func__, __LINE__);
		return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
	}

	/* Build test status file path */
	if (output_dir) {
		strcpy(file_path, output_dir);
		strcat(file_path, "/");
	} else {
		strcpy(file_path, DEFAULT_OUT_STATUS_PATH);
	}
	strcat(file_path, test_name);
	strcat(file_path, TEST_STATUS_EXTENSION);

	status_file = fopen(file_path, "w+");
	if (!status_file) {
		DBG_PRINT("fopen failed, file is %s", file_path);
		test_status = ERR_CODE(INTERNAL);
		goto exit;
	}

	res = file_to_json_object(test_definition_file, &definition_obj);
	if (res != ERR_CODE(PASSED)) {
		FPRINT_TEST_INTERNAL_FAILURE(status_file, test_name);
		test_status = res;
		goto exit;
	}

	/* Run subtests */
	json_object_object_foreachC(definition_obj, iter)
	{
		run_subtest(&iter, status_file, &test_status);
	}

	key_identifier_clear_list(key_identifiers);

	if (!test_status)
		FPRINT_TEST_STATUS(status_file, test_name,
				   (char *)ERR_STATUS(PASSED));
	else
		FPRINT_TEST_STATUS(status_file, test_name, ERR_STATUS(FAILED));

exit:
	if (file_path)
		free(file_path);

	fclose(status_file);

	return test_status;
}