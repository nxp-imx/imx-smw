// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include "json.h"
#include "util.h"
#include "util_key.h"
#include "util_context.h"
#include "types.h"
#include "keymgr.h"
#include "hash.h"
#include "sign_verify.h"
#include "hmac.h"
#include "rng.h"
#include "cipher.h"
#include "operation_context.h"
#include "config.h"
#include "run.h"
#include "paths.h"
#include "info.h"
#include "smw_osal.h"
#include "smw_status.h"

/* Key identifiers linked list */
static struct llist *key_identifiers;

/* Operation context linked list */
static struct llist *ctx_list;

/**
 * execute_generate_cmd() - Execute generate key command.
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
static int execute_generate_cmd(struct json_object *params,
				struct common_parameters *common_params,
				struct llist **key_ids,
				enum smw_status_code *status)
{
	/* Check mandatory params */
	if (!common_params->subsystem) {
		DBG_PRINT_MISS_PARAM(__func__, "subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return generate_key(params, common_params, key_ids, status);
}

/**
 * execute_hash_cmd() - Execute hash command.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_hash_cmd(struct json_object *params,
			    struct common_parameters *common_params,
			    enum smw_status_code *status)
{
	/* Check mandatory params */
	if (!common_params->subsystem) {
		DBG_PRINT_MISS_PARAM(__func__, "subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return hash(params, common_params, status);
}

/**
 * execute_hmac_cmd() - Execute hmac command.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hmac().
 */
static int execute_hmac_cmd(struct json_object *params,
			    struct common_parameters *common_params,
			    struct llist *key_ids, enum smw_status_code *status)
{
	/* Check mandatory params */
	if (!common_params->subsystem) {
		DBG_PRINT_MISS_PARAM(__func__, "subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return hmac(params, common_params, key_ids, status);
}

/**
 * execute_import_cmd() - Execute import key command.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from import_key().
 */
static int execute_import_cmd(struct json_object *params,
			      struct common_parameters *common_params,
			      struct llist **key_ids,
			      enum smw_status_code *status)
{
	/* Check mandatory params */
	if (!common_params->subsystem) {
		DBG_PRINT_MISS_PARAM(__func__, "subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return import_key(params, common_params, key_ids, status);
}

/**
 * execute_export_cmd() - Execute export command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from export_key().
 */
static int execute_export_cmd(char *cmd, struct json_object *params,
			      struct common_parameters *common_params,
			      struct llist *key_ids,
			      enum smw_status_code *status)
{
	if (!strcmp(cmd, EXPORT_KEYPAIR))
		return export_key(params, common_params, EXP_KEYPAIR, key_ids,
				  status);
	else if (!strcmp(cmd, EXPORT_PRIVATE))
		return export_key(params, common_params, EXP_PRIV, key_ids,
				  status);
	else if (!strcmp(cmd, EXPORT_PUBLIC))
		return export_key(params, common_params, EXP_PUB, key_ids,
				  status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_derive_cmd() - Execute derive command.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from derive_key().
 */
static int execute_derive_cmd(struct json_object *params,
			      struct common_parameters *common_params,
			      struct llist **key_ids,
			      enum smw_status_code *status)
{
	return derive_key(params, common_params, key_ids, status);
}

/**
 * execute_sign_verify_cmd() - Execute sign or verify command.
 * @operation: SIGN_OPERATION or VERIFY_OPERATION.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from sign_verify().
 */
static int execute_sign_verify_cmd(int operation, struct json_object *params,
				   struct common_parameters *common_params,
				   struct llist *key_ids,
				   enum smw_status_code *status)
{
	/* Check mandatory params */
	if (!common_params->subsystem) {
		DBG_PRINT_MISS_PARAM(__func__, "subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return sign_verify(operation, params, common_params, key_ids, status);
}

/**
 * execute_rng_cmd() - Execute RNG command.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_rng_cmd(struct json_object *params,
			   struct common_parameters *common_params,
			   enum smw_status_code *status)
{
	/* Check mandatory params */
	if (!common_params->subsystem) {
		DBG_PRINT_MISS_PARAM(__func__, "subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return rng(params, common_params, status);
}

/**
 * execute_cipher() - Execute cipher command
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @ctx: Pointer to context linked list.
 * @status: Pointer to SMW command status.
 *
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from cipher().
 * Error code from cipher_init().
 * Error code from cipher_update().
 * Error code from cipher_final().
 */
static int execute_cipher(char *cmd, struct json_object *params,
			  struct common_parameters *common_params,
			  struct llist *key_ids, struct llist **ctx,
			  enum smw_status_code *status)
{
	if (!strcmp(cmd, CIPHER))
		return cipher(params, common_params, key_ids, status);
	else if (!strcmp(cmd, CIPHER_INIT))
		return cipher_init(params, common_params, key_ids, ctx, status);
	else if (!strcmp(cmd, CIPHER_UPDATE))
		return cipher_update(params, common_params, *ctx, status);
	else if (!strcmp(cmd, CIPHER_FINAL))
		return cipher_final(params, common_params, *ctx, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_operation_context() - Execute an operation context operation
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @ctx: Pointer to context linked list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from cancel_operation().
 * Error code from copy_context().
 */
static int execute_operation_context(char *cmd, struct json_object *params,
				     struct common_parameters *common_params,
				     struct llist **ctx,
				     enum smw_status_code *status)
{
	if (!strcmp(cmd, OP_CTX_CANCEL))
		return cancel_operation(params, common_params, *ctx, status);
	else if (!strcmp(cmd, OP_CTX_COPY))
		return copy_context(params, common_params, ctx, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_config_cmd() - Execute configuration load or unload command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from smw_config_load() and smw_config_unload().
 */
static int execute_config_cmd(char *cmd, struct json_object *params,
			      struct common_parameters *common_params,
			      enum smw_status_code *status)
{
	if (!strcmp(cmd, CONFIG_LOAD))
		return config_load(params, common_params, status);
	if (!strcmp(cmd, CONFIG_UNLOAD))
		return config_unload(params, common_params, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_command() - Execute a subtest command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @common_params: Some parameters common to commands.
 * @key_ids: Pointer to key identifiers list.
 * @ctx: Pointer to context linked list.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Other error code otherwise.
 */
static int execute_command(char *cmd, struct json_object *params,
			   struct common_parameters *common_params,
			   struct llist **key_ids, struct llist **ctx,
			   enum smw_status_code *status)
{
	if (!strcmp(cmd, DELETE))
		return delete_key(params, common_params, *key_ids, status);
	else if (!strcmp(cmd, GENERATE))
		return execute_generate_cmd(params, common_params, key_ids,
					    status);
	else if (!strcmp(cmd, IMPORT))
		return execute_import_cmd(params, common_params, key_ids,
					  status);
	else if (!strncmp(cmd, EXPORT, strlen(EXPORT)))
		return execute_export_cmd(cmd, params, common_params, *key_ids,
					  status);
	else if (!strcmp(cmd, DERIVE))
		return execute_derive_cmd(params, common_params, key_ids,
					  status);
	else if (!strcmp(cmd, HASH))
		return execute_hash_cmd(params, common_params, status);
	else if (!strcmp(cmd, HMAC))
		return execute_hmac_cmd(params, common_params, *key_ids,
					status);
	else if (!strcmp(cmd, SIGN))
		return execute_sign_verify_cmd(SIGN_OPERATION, params,
					       common_params, *key_ids, status);
	else if (!strcmp(cmd, VERIFY))
		return execute_sign_verify_cmd(VERIFY_OPERATION, params,
					       common_params, *key_ids, status);
	else if (!strcmp(cmd, RNG))
		return execute_rng_cmd(params, common_params, status);
	else if (!strncmp(cmd, CIPHER, strlen(CIPHER)))
		return execute_cipher(cmd, params, common_params, *key_ids, ctx,
				      status);
	else if (!strncmp(cmd, OP_CTX, strlen(OP_CTX)))
		return execute_operation_context(cmd, params, common_params,
						 ctx, status);
	else if (!strncmp(cmd, CONFIG, strlen(CONFIG)))
		return execute_config_cmd(cmd, params, common_params, status);
	else if (!strcmp(cmd, SAVE_KEY_IDS))
		return save_key_ids_to_file(params, common_params, *key_ids,
					    status);
	else if (!strcmp(cmd, RESTORE_KEY_IDS))
		return restore_key_ids_from_file(params, common_params, key_ids,
						 status);
	else if (!strcmp(cmd, GET_VERSION))
		return get_info(params, common_params, status);

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
			 int *test_status, enum smw_status_code status)
{
	unsigned int idx = 0;

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
 * get_depends_status() - Handle 'depends' test definition parameter.
 * @params: Test definition parameters.
 * @status_file: Pointer to current status file.
 *
 * If 'depends' parameter is set in the test definition file check that
 * associated subtest(s) succeed.
 * 'depends' parameter can be an integer or an array of integer in case there
 * are multiple dependencies.
 * If at least one dependent subtest failed, current subtest is skipped.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_PARAM_TYPE	- Parameter is not correctly set.
 * -INTERNAL		- Internal error.
 * -NOT_RUN		- Subtest is skipped.
 */
static int get_depends_status(struct json_object *params, FILE *status_file)
{
	int i;
	int depends;
	int nb_members = 1;
	long fsave_pos;
	char depends_status[SUBTEST_STATUS_PASSED_MAX_LEN] = { 0 };
	char file_line[SUBTEST_STATUS_PASSED_MAX_LEN] = { 0 };
	char *read;
	json_object *depends_obj = NULL;
	json_object *array_member = NULL;

	if (!json_object_object_get_ex(params, DEPENDS_OBJ, &depends_obj))
		return ERR_CODE(PASSED);

	if (json_object_get_type(depends_obj) == json_type_array) {
		nb_members = json_object_array_length(depends_obj);

		/*
		 * 'depends' parameter must be an array only for multiple
		 * entries. Otherwise it must be an integer
		 */
		if (nb_members <= 1) {
			DBG_PRINT_BAD_PARAM(__func__, DEPENDS_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}
	}

	for (i = 0; i < nb_members; i++) {
		if (nb_members > 1)
			array_member =
				json_object_array_get_idx(depends_obj, i);
		else
			array_member = depends_obj;

		depends = json_object_get_int(array_member);
		if (depends <= 0) {
			DBG_PRINT_BAD_PARAM(__func__, DEPENDS_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		/* Expected dependent subtest status */
		if (sprintf(depends_status, "%s%d: PASSED\n", SUBTEST_OBJ,
			    depends) < 0)
			return ERR_CODE(INTERNAL);

		/* Backup current status file position */
		fsave_pos = ftell(status_file);
		if (fsave_pos == -1)
			return ERR_CODE(INTERNAL);

		/* Set status file position to beginning */
		if (fseek(status_file, 0, SEEK_SET))
			return ERR_CODE(INTERNAL);

		depends = 0;

		while (fgets(file_line, sizeof(file_line), status_file)) {
			read = strchr(file_line, '\n');
			if (read)
				*read = '\0';

			if (!strncmp(file_line, depends_status,
				     strlen(file_line))) {
				depends = 1;
				break;
			}
		};

		/* Restore status file position */
		if (fseek(status_file, fsave_pos, SEEK_SET))
			return ERR_CODE(INTERNAL);

		if (!depends)
			return ERR_CODE(NOT_RUN);
	}

	return ERR_CODE(PASSED);
}

/**
 * run_subtest() - Run a subtest.
 * @obj_iter: Pointer to json object iterator of the json definition file
 *            object.
 * @status_file: Pointer to the test status file.
 * @is_api_test: Define if it's an API test or not
 * @test_status: Pointer to the test status variable.
 *
 * Return:
 * none.
 */
static void run_subtest(struct json_object_iter *obj_iter, FILE *status_file,
			int is_api_test, int *test_status)
{
	int res = ERR_CODE(FAILED);
	enum smw_status_code status = SMW_STATUS_OPERATION_FAILURE;
	char *command_name = NULL;
	char *expected_status = NULL;
	char *sub_status = NULL;
	const char *sub_error = NULL;
	const char *sub_used = NULL;
	const char *sub_exp = NULL;
	struct common_parameters common_params = { 0 };
	json_object *cmd_obj = NULL;
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

	common_params.is_api_test = is_api_test;

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

	if (json_object_object_get_ex(obj_iter->val, SUBSYSTEM_OBJ, &sub_obj))
		common_params.subsystem =
			(char *)json_object_get_string(sub_obj);

	/* Check dependent subtest(s) status */
	res = get_depends_status(obj_iter->val, status_file);
	if (res != ERR_CODE(PASSED))
		goto exit;

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

	/*
	 * Get expected subsystem to be used.
	 * If not set in test definition file don't verify it.
	 */
	res = util_read_json_type(&sub_exp, SUBSYSTEM_EXP_OBJ, t_string,
				  obj_iter->val);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Execute subtest command */
	res = execute_command(command_name, obj_iter->val, &common_params,
			      &key_identifiers, &ctx_list, &status);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (sub_exp) {
		sub_used = smw_read_latest_subsystem_name();
		if (sub_used) {
			DBG_PRINT("Selected subsystem: %s", sub_used);
			if (strcmp(sub_used, sub_exp)) {
				DBG_PRINT("Expected subsystem: %s", sub_exp);
				res = ERR_CODE(BAD_RESULT);
			}
		} else {
			DBG_PRINT("WARNING - subsystem cannot be verified!");
		}
	}

exit:
	res = update_status(res, &sub_status, &sub_error, test_status, status);

	FPRINT_SUBTEST_STATUS(status_file, obj_iter->key, sub_status,
			      sub_error);
	FPRINT_SUBTEST_STATUS(stdout, obj_iter->key, sub_status, sub_error);
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
	int is_api_test = 0;

	if (!test_definition_file || !test_name) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	file_path_size = strlen(test_name) + strlen(TEST_STATUS_EXTENSION);

	if (output_dir)
		file_path_size += strlen(output_dir) + 1;
	else
		file_path_size += strlen(DEFAULT_OUT_STATUS_PATH);

	/*
	 * Allocate test file result full pathname
	 * null terminated string.
	 */
	file_path = malloc(file_path_size + 1);
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
	file_path[file_path_size] = '\0';

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

	/*
	 * Check from test name if it's a test to verify the API only
	 */
	if (strstr(test_name, TEST_API_TYPE))
		is_api_test = 1;

	/* Run subtests */
	json_object_object_foreachC(definition_obj, iter)
	{
		run_subtest(&iter, status_file, is_api_test, &test_status);
	}

	util_list_clear(key_identifiers);
	sign_clear_signatures_list();
	util_list_clear(ctx_list);
	cipher_clear_out_data_list();

	if (!test_status)
		FPRINT_TEST_STATUS(status_file, test_name,
				   (char *)ERR_STATUS(PASSED));
	else
		FPRINT_TEST_STATUS(status_file, test_name, ERR_STATUS(FAILED));

exit:
	if (file_path)
		free(file_path);

	if (status_file)
		(void)fclose(status_file);

	if (definition_obj)
		json_object_put(definition_obj);

	return test_status;
}
