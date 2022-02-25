// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <string.h>

#include "smw_osal.h"

#include "util_cond.h"
#include "util_log.h"
#include "util_sem.h"
#include "util_thread.h"
#include "keymgr.h"
#include "hash.h"
#include "sign_verify.h"
#include "hmac.h"
#include "rng.h"
#include "cipher.h"
#include "operation_context.h"
#include "config.h"
#include "info.h"

/**
 * execute_delete_key_cmd() - Execute delete key command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * Error code from delete_key().
 */
static int execute_delete_key_cmd(char *cmd, struct json_object *params,
				  struct cmn_params *cmn_params,
				  enum smw_status_code *status)
{
	(void)cmd;

	return delete_key(params, cmn_params, status);
}

/**
 * execute_generate_cmd() - Execute generate key command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED          - Passed.
 * -MISSING_PARAMS - Subsystem missing
 * Error code from generate_key().
 */
static int execute_generate_cmd(char *cmd, struct json_object *params,
				struct cmn_params *cmn_params,
				enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return generate_key(params, cmn_params, status);
}

/**
 * execute_hash_cmd() - Execute hash command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_hash_cmd(char *cmd, struct json_object *params,
			    struct cmn_params *cmn_params,
			    enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return hash(params, cmn_params, status);
}

/**
 * execute_hmac_cmd() - Execute hmac command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hmac().
 */
static int execute_hmac_cmd(char *cmd, struct json_object *params,
			    struct cmn_params *cmn_params,
			    enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return hmac(params, cmn_params, status);
}

/**
 * execute_import_cmd() - Execute import key command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from import_key().
 */
static int execute_import_cmd(char *cmd, struct json_object *params,
			      struct cmn_params *cmn_params,
			      enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return import_key(params, cmn_params, status);
}

/**
 * execute_export_cmd() - Execute export command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from export_key().
 */
static int execute_export_cmd(char *cmd, struct json_object *params,
			      struct cmn_params *cmn_params,
			      enum smw_status_code *status)
{
	if (!strcmp(cmd, EXPORT_KEYPAIR))
		return export_key(params, cmn_params, EXP_KEYPAIR, status);
	else if (!strcmp(cmd, EXPORT_PRIVATE))
		return export_key(params, cmn_params, EXP_PRIV, status);
	else if (!strcmp(cmd, EXPORT_PUBLIC))
		return export_key(params, cmn_params, EXP_PUB, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_derive_cmd() - Execute derive command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from derive_key().
 */
static int execute_derive_cmd(char *cmd, struct json_object *params,
			      struct cmn_params *cmn_params,
			      enum smw_status_code *status)
{
	(void)cmd;

	return derive_key(params, cmn_params, status);
}

/**
 * execute_sign_cmd() - Execute sign command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from sign_verify().
 */
static int execute_sign_cmd(char *cmd, struct json_object *params,
			    struct cmn_params *cmn_params,
			    enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return sign_verify(SIGN_OPERATION, params, cmn_params, status);
}

/**
 * execute_sign_verify_cmd() - Execute sign or verify command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from sign_verify().
 */
static int execute_verify_cmd(char *cmd, struct json_object *params,
			      struct cmn_params *cmn_params,
			      enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return sign_verify(VERIFY_OPERATION, params, cmn_params, status);
}

/**
 * execute_rng_cmd() - Execute RNG command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from hash().
 */
static int execute_rng_cmd(char *cmd, struct json_object *params,
			   struct cmn_params *cmn_params,
			   enum smw_status_code *status)
{
	(void)cmd;

	/* Check mandatory params */
	if (!cmn_params->subsystem) {
		DBG_PRINT_MISS_PARAM("subsystem");
		return ERR_CODE(MISSING_PARAMS);
	}

	return rng(params, cmn_params, status);
}

/**
 * execute_cipher_cmd() - Execute cipher command
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from cipher().
 * Error code from cipher_init().
 * Error code from cipher_update().
 * Error code from cipher_final().
 */
static int execute_cipher_cmd(char *cmd, struct json_object *params,
			      struct cmn_params *cmn_params,
			      enum smw_status_code *status)
{
	if (!strcmp(cmd, CIPHER))
		return cipher(params, cmn_params, status);
	else if (!strcmp(cmd, CIPHER_INIT))
		return cipher_init(params, cmn_params, status);
	else if (!strcmp(cmd, CIPHER_UPDATE))
		return cipher_update(params, cmn_params, status);
	else if (!strcmp(cmd, CIPHER_FINAL))
		return cipher_final(params, cmn_params, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_operation_context() - Execute an operation context operation
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from cancel_operation().
 * Error code from copy_context().
 */
static int execute_op_context_cmd(char *cmd, struct json_object *params,
				  struct cmn_params *cmn_params,
				  enum smw_status_code *status)
{
	if (!strcmp(cmd, OP_CTX_CANCEL))
		return cancel_operation(params, cmn_params, status);
	else if (!strcmp(cmd, OP_CTX_COPY))
		return copy_context(params, cmn_params, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_config_cmd() - Execute configuration load or unload command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Error code from smw_config_load() and smw_config_unload().
 */
static int execute_config_cmd(char *cmd, struct json_object *params,
			      struct cmn_params *cmn_params,
			      enum smw_status_code *status)
{
	if (!strcmp(cmd, CONFIG_LOAD))
		return config_load(params, cmn_params, status);
	if (!strcmp(cmd, CONFIG_UNLOAD))
		return config_unload(params, cmn_params, status);

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * execute_save_keys_cmd() - Execute backup keys ids in a file
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -MISSING_PARAMS	- Missing mandatory parameters in @params.
 * -BAD_RESULT		- SMW API status differs from expected one.
 * -BAD_ARGS		- One of the arguments is bad.
 * -UNDEFINED_CMD	- Command is undefined.
 */
static int execute_save_keys_cmd(char *cmd, struct json_object *params,
				 struct cmn_params *cmn_params,
				 enum smw_status_code *status)
{
	(void)cmd;

	return save_key_ids_to_file(params, cmn_params, status);
}

/**
 * execute_restore_keys_cmd() - Execute restore keys ids from a file
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED                  - Success.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params.
 * -BAD_RESULT             - SMW API status differs from expected one.
 * -BAD_ARGS               - One of the arguments is bad.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
static int execute_restore_keys_cmd(char *cmd, struct json_object *params,
				    struct cmn_params *cmn_params,
				    enum smw_status_code *status)
{
	(void)cmd;

	return restore_key_ids_from_file(params, cmn_params, status);
}

/**
 * execute_get_version_cmd() - Execute get version commands
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_RESULT		- SMW API status differs from expected one.
 * -BAD_ARGS		- One of the arguments is bad.
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 * -VALUE_NOTFOUND	- Test definition Value not found.
 * -FAILED		- Test failed
 */
static int execute_get_version_cmd(char *cmd, struct json_object *params,
				   struct cmn_params *cmn_params,
				   enum smw_status_code *status)
{
	(void)cmd;

	return get_info(params, cmn_params, status);
}

/**
 * execute_command() - Execute a subtest command.
 * @cmd: Command name.
 * @params: Command parameters.
 * @cmn_params: Some parameters common to commands.
 * @status: Pointer to SMW command status.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Other error code otherwise.
 */
static int execute_command(char *cmd, struct json_object *params,
			   struct cmn_params *cmn_params,
			   enum smw_status_code *status)
{
	static struct cmd_op {
		const char *cmd_prefix;
		int (*op)(char *cmd, struct json_object *params,
			  struct cmn_params *cmn_params,
			  enum smw_status_code *status);
	} cmd_list[] = {
		{ DELETE, &execute_delete_key_cmd },
		{ GENERATE, &execute_generate_cmd },
		{ IMPORT, &execute_import_cmd },
		{ EXPORT, &execute_export_cmd },
		{ DERIVE, &execute_derive_cmd },
		{ HASH, &execute_hash_cmd },
		{ HMAC, &execute_hmac_cmd },
		{ SIGN, &execute_sign_cmd },
		{ VERIFY, &execute_verify_cmd },
		{ RNG, &execute_rng_cmd },
		{ CIPHER, &execute_cipher_cmd },
		{ OP_CTX, &execute_op_context_cmd },
		{ CONFIG, &execute_config_cmd },
		{ SAVE_KEY_IDS, &execute_save_keys_cmd },
		{ RESTORE_KEY_IDS, &execute_restore_keys_cmd },
		{ GET_VERSION, &execute_get_version_cmd },
	};

	for (size_t idx = 0; idx < ARRAY_SIZE(cmd_list); idx++) {
		if (!strncmp(cmd, cmd_list[idx].cmd_prefix,
			     strlen(cmd_list[idx].cmd_prefix))) {
			return cmd_list[idx].op(cmd, params, cmn_params,
						status);
		}
	}

	DBG_PRINT("Undefined command");
	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * is_subtest_passed() - Return if a subtest passed
 * @thr: Thread data
 * @id: Subtest id
 *
 * Read the application log file and retrieve if the subtest @id passed
 * or not.
 *
 * Return:
 * PASSED          - Subtest passed
 * -FAILED         - Subtest failed
 * -INTERNAL       - Internal error when accessing the log
 */
static int is_subtest_passed(struct thread_data *thr, int id)
{
	char str[256] = { 0 };

	if (strlen(thr->name))
		(void)sprintf(str, "[%s] %s%d: %s", thr->name, SUBTEST_OBJ, id,
			      util_get_err_code_str(ERR_CODE(PASSED)));
	else
		(void)sprintf(str, "%s%d: %s", SUBTEST_OBJ, id,
			      util_get_err_code_str(ERR_CODE(PASSED)));

	return util_log_find(thr->app, str);
}

/**
 * get_depends_status() - Handle 'depends' test definition parameter.
 * @thr: Thread data
 * @def: Test definition parameters.
 *
 * If 'depends' parameter is set in the test definition file check that
 * associated subtest(s) succeed.
 * 'depends' parameter can be an integer or an array of integer in case there
 * are multiple dependencies.
 * If at least one dependent subtest failed, current subtest is skipped.
 *
 * Return:
 * PASSED           - Success.
 * -BAD_PARAM_TYPE  - Parameter is not correctly set.
 * -INTERNAL        - Internal error.
 * -NOT_RUN         - Subtest is skipped.
 * -FAILED          - Failure
 */
static int get_depends_status(struct thread_data *thr, struct json_object *def)
{
	int res;
	int dep_id;
	int nb_members = 1;
	json_object *depends_obj = NULL;
	json_object *oval = NULL;

	res = util_read_json_type(&depends_obj, DEPENDS_OBJ, t_buffer, def);
	if (res != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (res == ERR_CODE(VALUE_NOTFOUND))
			res = ERR_CODE(PASSED);

		return res;
	}

	switch (json_object_get_type(depends_obj)) {
	case json_type_int:
		dep_id = json_object_get_int(depends_obj);
		res = is_subtest_passed(thr, dep_id);
		if (res == ERR_CODE(FAILED))
			res = ERR_CODE(NOT_RUN);
		break;

	case json_type_array:
		nb_members = json_object_array_length(depends_obj);

		/*
		 * 'depends' parameter must be an array only for multiple
		 * entries. Otherwise it must be an integer
		 */
		if (nb_members < 2) {
			DBG_PRINT_BAD_PARAM(DEPENDS_OBJ);
			return ERR_CODE(BAD_PARAM_TYPE);
		}

		for (int i = 0; i < nb_members; i++) {
			/* Get the subtest id number */
			oval = json_object_array_get_idx(depends_obj, i);
			if (json_object_get_type(oval) != json_type_int) {
				DBG_PRINT("%s must be an array of integer",
					  DEPENDS_OBJ);
				return ERR_CODE(BAD_PARAM_TYPE);
			}

			dep_id = json_object_get_int(oval);
			res = is_subtest_passed(thr, dep_id);
			if (res == ERR_CODE(FAILED)) {
				res = ERR_CODE(NOT_RUN);
				break;
			}
		}

		break;

	default:
		res = ERR_CODE(INTERNAL);
	}

	return res;
}

/**
 * run_subtest() - Run a subtest.
 * @thr: Thread data
 * @obj: Operation object data
 */
static void run_subtest(struct thread_data *thr, struct json_object *obj)
{
	int res = ERR_CODE(FAILED);
	char *cmd_name = NULL;
	char *expected_status = NULL;
	const char *sub_used = NULL;
	const char *sub_exp = NULL;
	struct cmn_params cmn_params = { 0 };

	cmn_params.app = thr->app;
	thr->subtest->smw_status = SMW_STATUS_OPERATION_FAILURE;

	/* Verify the type of the subtest tag/value is json object */
	if (json_object_get_type(obj) != json_type_object) {
		FPRINT_MESSAGE(thr->app, "Error in test definiton file: ");
		FPRINT_MESSAGE(thr->app,
			       "\"subtest\" is not a json-c object\n");
		DBG_PRINT("\"subtest\" is not a json-c object");

		res = ERR_CODE(BAD_PARAM_TYPE);
		goto exit;
	}

	/* 'command' is a mandatory parameter */
	res = util_read_json_type(&cmd_name, CMD_OBJ, t_string, obj);
	if (res != ERR_CODE(PASSED)) {
		if (res == ERR_CODE(VALUE_NOTFOUND)) {
			DBG_PRINT_MISS_PARAM(CMD_OBJ);
			res = ERR_CODE(MISSING_PARAMS);
		}

		goto exit;
	}

	res = util_read_json_type(&cmn_params.subsystem, SUBSYSTEM_OBJ,
				  t_string, obj);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Check dependent subtest(s) status */
	res = get_depends_status(thr, obj);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Get expected result parameter 'result' set in test definition file.
	 * If not defined, the default value is SMW_STATUS_OK.
	 */
	res = util_read_json_type(&expected_status, RES_OBJ, t_string, obj);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (expected_status) {
		res = get_smw_int_status(&cmn_params.expected_res,
					 expected_status);

		if (res != ERR_CODE(PASSED))
			goto exit;

	} else {
		cmn_params.expected_res = SMW_STATUS_OK;
	}

	/*
	 * Get SMW API version.
	 * If not set in test definition file, use default value.
	 */
	cmn_params.version = SMW_API_DEFAULT_VERSION;
	res = util_read_json_type(&cmn_params.version, VERSION_OBJ, t_int, obj);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/*
	 * Get expected subsystem to be used.
	 * If not set in test definition file don't verify it.
	 */
	res = util_read_json_type(&sub_exp, SUBSYSTEM_EXP_OBJ, t_string, obj);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* First wait and post semaphore */
	res = util_sem_wait_before(thr, obj);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_sem_post_before(thr, obj);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Execute subtest command */
	res = execute_command(cmd_name, obj, &cmn_params,
			      &thr->subtest->smw_status);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Last wait and post semaphore */
	res = util_sem_post_after(thr, obj);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = util_sem_wait_after(thr, obj);
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
	thr->subtest->status = res;

	if (res == ERR_CODE(PASSED))
		thr->subtests_passed++;

	if (thr->status == ERR_CODE(PASSED))
		thr->status = res;

	util_thread_log(thr);
}

void *process_thread(void *arg)
{
	int err = ERR_CODE(BAD_ARGS);
	int i;
	struct thread_data *thr = arg;
	struct json_object_iter obj;
	struct subtest_data subtest = { 0 };

	if (!thr || !thr->def) {
		DBG_PRINT_BAD_ARGS();
		exit(ERR_CODE(BAD_ARGS));
	}

	if (!json_object_get_object(thr->def)) {
		DBG_PRINT("Thread definition json_object_get_object error");
		thr->status = ERR_CODE(INTERNAL);
		goto exit;
	}

	thr->state = STATE_RUNNING;
	thr->status = ERR_CODE(PASSED);

	/* First wait and post semaphore if multi-thread test */
	err = util_sem_wait_before(thr, thr->parent_def);
	if (err != ERR_CODE(PASSED)) {
		thr->status = err;
		goto exit;
	}

	err = util_sem_post_before(thr, thr->parent_def);
	if (err != ERR_CODE(PASSED)) {
		thr->status = err;
		goto exit;
	}

	thr->subtests_total = 0;
	thr->subtests_passed = 0;

	for (i = 0; i < thr->loop + 1; i++) {
		thr->subtest = &subtest;
		json_object_object_foreachC(thr->def, obj)
		{
			/* Run the JSON-C "subtest" object, other tag is ignored */
			if (strncmp(obj.key, SUBTEST_OBJ, strlen(SUBTEST_OBJ)))
				continue;

			thr->subtests_total++;
			thr->subtest->name = obj.key;
			run_subtest(thr, obj.val);
		}
	}

	thr->subtest = NULL;

	/* If no subtests ran - Failure */
	if (!thr->subtests_total)
		thr->status = ERR_CODE(FAILED);

	/* Last wait and post semaphore if multi-thread test */
	err = util_sem_post_after(thr, thr->parent_def);
	if (err != ERR_CODE(PASSED))
		goto exit;

	err = util_sem_wait_after(thr, thr->parent_def);

exit:
	thr->state = STATE_EXITED;

	if (thr->status == ERR_CODE(PASSED))
		thr->status = err;

	util_thread_log(thr);

	/* Decrement (free) the thread JSON-C definition */
	if (thr->def)
		json_object_put(thr->def);

	return &thr->status;
}
