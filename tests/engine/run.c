// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <string.h>

#include "smw_osal.h"

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

/* Key identifiers linked list */
static struct llist *key_identifiers;

/* Operation context linked list */
static struct llist *ctx_list;

static const struct tee_info tee_default_info = {
	{ "11b5c4aa-6d20-11ea-bc55-0242ac130003" }
};

static const struct se_info se_default_info = { 0x534d5754, 0x444546,
						1000 }; // SMWT, DEF

struct obj_operation {
	struct json_object_iter obj;
	FILE *log;
	int is_api_test;
};

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
 * log_subtest_status() - Log the subtest status
 * @op: Subtest status to update (PASSED or FAILED).
 * @res: Result of the subtest.
 * @status: SMW Library status.
 *
 * Log the subtest name and the reason of the failure if any.
 * Function returns if overall test passed or failed.
 *
 * Return:
 * PASSED - subtest passed
 * -FAILED - subtest failed
 */
static int log_subtest_status(struct obj_operation *op, int res,
			      enum smw_status_code status)
{
	int ret = FAILED;
	unsigned int idx = 0;
	const char *error = NULL;

	printf("operation res %d with %x\n", res, status);
	/* Find the error entry in the array of error string */
	for (; idx < list_err_size && res != ERR_CODE(idx); idx++)
		;

	switch (idx) {
	case PASSED:
		ret = PASSED;
		break;

	case BAD_RESULT:
		error = get_smw_string_status(status);
		break;

	default:
		if (idx < list_err_size)
			error = ERR_STATUS(idx);
		else
			error = ERR_STATUS(INTERNAL);

		break;
	}

	FPRINT_SUBTEST_STATUS(op->log, op->obj.key, ERR_STATUS(ret), error);
	FPRINT_SUBTEST_STATUS(stdout, op->obj.key, ERR_STATUS(ret), error);

	return ERR_CODE(ret);
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
 * @op: Operation object data
 *
 * Return:
 * PASSED - subtest passed
 * -FAILED - subtest failed
 */
static int run_subtest(struct obj_operation *op)
{
	int res = ERR_CODE(FAILED);
	enum smw_status_code status = SMW_STATUS_OPERATION_FAILURE;
	char *cmd_name = NULL;
	char *expected_status = NULL;
	const char *sub_used = NULL;
	const char *sub_exp = NULL;
	struct common_parameters common_params = { 0 };

	if (!op) {
		DBG_PRINT_BAD_ARGS(__func__);
		return res;
	}

	common_params.is_api_test = op->is_api_test;

	/* Verify the presence of subtest json object */
	if (json_object_get_type(op->obj.val) != json_type_object) {
		FPRINT_MESSAGE(op->log, "Error in test definiton file: ");
		FPRINT_MESSAGE(op->log, "\"subtest\" is not a JSON-C object\n");
		DBG_PRINT("\"subtest\" is not a JSON-C object");

		res = ERR_CODE(BAD_PARAM_TYPE);
		goto exit;
	}

	/* 'command' is a mandatory parameter */
	res = util_read_json_type(&cmd_name, CMD_OBJ, t_string, op->obj.val);
	if (res != ERR_CODE(PASSED)) {
		if (res == ERR_CODE(VALUE_NOTFOUND)) {
			DBG_PRINT_MISS_PARAM(__func__, CMD_OBJ);
			res = ERR_CODE(MISSING_PARAMS);
		}

		goto exit;
	}

	res = util_read_json_type(&common_params.subsystem, SUBSYSTEM_OBJ,
				  t_string, op->obj.val);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Check dependent subtest(s) status */
	res = get_depends_status(op->obj.val, op->log);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Get expected result parameter 'result' set in test definition file.
	 * If not defined, the default value is SMW_STATUS_OK.
	 */
	res = util_read_json_type(&expected_status, RES_OBJ, t_string,
				  op->obj.val);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (expected_status) {
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
	common_params.version = SMW_API_DEFAULT_VERSION;
	res = util_read_json_type(&common_params.version, VERSION_OBJ, t_int,
				  op->obj.val);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/*
	 * Get expected subsystem to be used.
	 * If not set in test definition file don't verify it.
	 */
	res = util_read_json_type(&sub_exp, SUBSYSTEM_EXP_OBJ, t_string,
				  op->obj.val);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Execute subtest command */
	res = execute_command(cmd_name, op->obj.val, &common_params,
			      &key_identifiers, &ctx_list, &status);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (sub_exp) {
		sub_used = smw_osal_latest_subsystem_name();
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
	return log_subtest_status(op, res, status);
}

/**
 * setup_tee_info() - Read and setup TEE Information
 * @test_def: JSON-C test definition of the application
 *
 * Function extracts TEE information from the test definition of
 * the application configuration and calls the SMW Library TEE Information
 * setup API.
 *
 * TEE info is defined with a JSON-C object "tee_info".
 *
 * Return:
 * PASSED              - Success.
 * -BAD_PARAM_TYPE     - Parameter type is not correct or not supported.
 * -BAD_ARGS           - One of the argument is bad.
 * -FAILED             - Error in definition file
 * -ERROR_SMWLIB_INIT  - SMW Library initialization error
 */
static int setup_tee_info(json_object *test_def)
{
	int res;
	struct tee_info info = tee_default_info;
	json_object *oinfo = NULL;
	char *ta_uuid = NULL;

	res = util_read_json_type(&oinfo, TEE_INFO_OBJ, t_object, test_def);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND) &&
	    !oinfo)
		return res;

	if (res == ERR_CODE(PASSED)) {
		res = util_read_json_type(&ta_uuid, TA_UUID, t_string, oinfo);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			return res;

		if (strlen(ta_uuid) + 1 > sizeof(info.ta_uuid))
			return ERR_CODE(BAD_PARAM_TYPE);

		memcpy(info.ta_uuid, ta_uuid, strlen(ta_uuid) + 1);
	}

	res = smw_osal_set_subsystem_info("TEE", &info, sizeof(info));
	if (res != SMW_STATUS_OK) {
		DBG_PRINT("SMW Set TEE Info failed %s",
			  get_smw_string_status(res));
		res = ERR_CODE(ERROR_SMWLIB_INIT);
	} else {
		res = ERR_CODE(PASSED);
	}

	return res;
}

/**
 * setup_hsm_info() - Read and setup HSM Secure Enclave Information
 * @test_def: JSON-C test definition of the application
 *
 * Function extracts HSM information from the test definition of
 * the application configuration and calls the SMW Library HSM Information
 * setup API.
 *
 * SE info is defined with a JSON-C object "hsm_info".
 *
 * Return:
 * PASSED              - Success.
 * -BAD_PARAM_TYPE     - Parameter type is not correct or not supported.
 * -BAD_ARGS           - One of the argument is bad.
 * -FAILED             - Error in definition file
 * -ERROR_SMWLIB_INIT  - SMW Library initialization error
 */
static int setup_hsm_info(json_object *test_def)
{
	int res;
	struct se_info info = se_default_info;
	json_object *oinfo = NULL;

	res = util_read_json_type(&oinfo, HSM_INFO_OBJ, t_object, test_def);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND) &&
	    !oinfo)
		return res;

	if (res == ERR_CODE(PASSED)) {
		res = UTIL_READ_JSON_ST_FIELD(&info, storage_id, int, oinfo);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			return res;

		res = UTIL_READ_JSON_ST_FIELD(&info, storage_nonce, int, oinfo);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			return res;

		res = UTIL_READ_JSON_ST_FIELD(&info, storage_replay, int,
					      oinfo);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			return res;
	}

	res = smw_osal_set_subsystem_info("HSM", &info, sizeof(info));
	if (res != SMW_STATUS_OK) {
		DBG_PRINT("SMW Set HSM Info failed %s",
			  get_smw_string_status(res));
		res = ERR_CODE(ERROR_SMWLIB_INIT);

	} else {
		res = ERR_CODE(PASSED);
	}

	return res;
}

/**
 * init_smwlib() - Initialize the SMW Library
 * @test_def: JSON-C test definition of the application
 *
 * Function extracts from the test definition the application configuration
 * and call the SMW Library inilization API.
 *
 * Return:
 * PASSED              - Success.
 * -ERROR_SMWLIB_INIT  - SMW Library initialization error
 */
static int init_smwlib(json_object *test_def)
{
	int res;

	res = setup_tee_info(test_def);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = setup_hsm_info(test_def);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = smw_osal_lib_init();
	if (res != SMW_STATUS_OK) {
		DBG_PRINT("SMW Library initialization failed %s",
			  get_smw_string_status(res));
		res = ERR_CODE(ERROR_SMWLIB_INIT);
	} else {
		res = ERR_CODE(PASSED);
	}

end:
	if (res != ERR_CODE(PASSED))
		res = ERR_CODE(ERROR_SMWLIB_INIT);

	return res;
}

/*
 * ignore_tag() - Ignore a JSON-C top tag/value
 * @obj: Operation object
 *
 * Return
 * PASSED - Success
 */
static int ignore_tag(struct obj_operation *obj)
{
	(void)obj;

	return ERR_CODE(PASSED);
}

/*
 * List of the operation per JSONC-C top tag/value
 */
const struct op_type {
	const char *name;
	int (*run)(struct obj_operation *obj);
} op_types[] = { { TEE_INFO_OBJ, &ignore_tag },
		 { HSM_INFO_OBJ, &ignore_tag },
		 { SUBTEST_OBJ, &run_subtest },
		 { NULL, NULL } };

int run_test(char *test_def_file, char *test_name, char *output_dir)
{
	int test_status = ERR_CODE(FAILED);
	int file_path_size = 0;
	char *file_path = NULL;
	json_object *definition_obj = NULL;
	struct obj_operation op = { 0 };
	const struct op_type *op_type;

	if (!test_def_file || !test_name) {
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

	op.log = fopen(file_path, "w+");
	if (!op.log) {
		DBG_PRINT("fopen failed, file is %s", file_path);
		test_status = ERR_CODE(INTERNAL);
		goto exit;
	}

	test_status = file_to_json_object(test_def_file, &definition_obj);
	if (test_status != ERR_CODE(PASSED)) {
		FPRINT_TEST_INTERNAL_FAILURE(op.log, test_name);
		goto exit;
	}

	test_status = init_smwlib(definition_obj);
	if (test_status != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Check from test name if it's a test to verify the API only
	 */
	if (strstr(test_name, TEST_API_TYPE))
		op.is_api_test = 1;

	/*
	 * For each test definition JSON-C top tag/value,
	 * search tag in the op_types list and execute action assiciated.
	 */
	json_object_object_foreachC(definition_obj, op.obj)
	{
		for (op_type = op_types; op_type->name; op_type++) {
			if (!strncmp(op.obj.key, op_type->name,
				     strlen(op_type->name))) {
				test_status |= op_type->run(&op);
				break;
			}
		}

		if (!op_type->name) {
			FPRINT_MESSAGE(op.log, "JSON-C tag name %s ignored\n",
				       op.obj.key);
			DBG_PRINT("WARNING: JSON-C object tag %s ignored",
				  op.obj.key);
		}
	}

	util_list_clear(key_identifiers);
	sign_clear_signatures_list();
	util_list_clear(ctx_list);
	cipher_clear_out_data_list();

	if (!test_status)
		FPRINT_TEST_STATUS(op.log, test_name, ERR_STATUS(PASSED));
	else
		FPRINT_TEST_STATUS(op.log, test_name, ERR_STATUS(FAILED));

exit:
	if (file_path)
		free(file_path);

	if (op.log)
		(void)fclose(op.log);

	if (definition_obj)
		json_object_put(definition_obj);

	return test_status;
}
