// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <string.h>

#include <smw_osal.h>

#include "compiler.h"
#include "util.h"
#include "util_log.h"
#include "util_sem.h"
#include "util_thread.h"
#include "util_rtcwake.h"
#include "util_key.h"
#include "exec_smw.h"
#include "exec_psa.h"

/**
 * execute_save_keys_cmd() - Execute backup keys in a file
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -MISSING_PARAMS	- Missing mandatory parameters in @params.
 * -BAD_RESULT		- SMW API status differs from expected one.
 * -BAD_ARGS		- One of the arguments is bad.
 * -UNDEFINED_CMD	- Command is undefined.
 */
static int execute_save_keys_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return util_key_save_keys_to_file(subtest);
}

/**
 * execute_restore_keys_cmd() - Execute restore keys from a file
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                  - Success.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params.
 * -BAD_RESULT             - SMW API status differs from expected one.
 * -BAD_ARGS               - One of the arguments is bad.
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed.
 */
static int execute_restore_keys_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	return util_key_restore_keys_from_file(subtest);
}

/**
 * execute_suspend_cmd() - Suspend the system
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -BAD_PARAM_TYPE          - Parameter type is not correct or not supported.
 * -BAD_ARGS                - One of the argument is bad.
 * -INTERNAL                - Internal function failed.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -VALUE_NOTFOUND          - Value not found.
 * -FAILED                  - Error in definition file
 */
static int execute_suspend_cmd(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;

	int res = ERR_CODE(PASSED);
	int sec = 0;

	res = util_read_json_type(&sec, SECONDS_OBJ, t_int, subtest->params);
	if (res == ERR_CODE(PASSED))
		res = util_rtcwake_suspend_to_mem(sec);

	return res;
}

__weak int execute_command_smw(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;
	(void)subtest;

	return ERR_CODE(UNDEFINED_API);
}

__weak int execute_command_psa(char *cmd, struct subtest_data *subtest)
{
	(void)cmd;
	(void)subtest;

	return ERR_CODE(UNDEFINED_API);
}

/**
 * execute_command() - Execute a subtest command.
 * @cmd: Command name.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Passed.
 * -UNDEFINED_CMD	- Command is undefined.
 * Other error code otherwise.
 */
static int execute_command(char *cmd, struct subtest_data *subtest)
{
	static struct cmd_op {
		const char *cmd_prefix;
		int (*op)(char *cmd, struct subtest_data *subtest);
	} cmd_list[] = {
		{ SAVE_KEY_IDS, &execute_save_keys_cmd },
		{ RESTORE_KEY_IDS, &execute_restore_keys_cmd },
		{ SUSPEND, &execute_suspend_cmd },
	};

	for (size_t idx = 0; idx < ARRAY_SIZE(cmd_list); idx++) {
		if (!strncmp(cmd, cmd_list[idx].cmd_prefix,
			     strlen(cmd_list[idx].cmd_prefix)))
			return cmd_list[idx].op(cmd, subtest);
	}

	if (!strcmp(subtest->api, "SMW"))
		return execute_command_smw(cmd, subtest);

	if (!strcmp(subtest->api, "PSA"))
		return execute_command_psa(cmd, subtest);

	DBG_PRINT("Undefined API type %s", subtest->api);

	return ERR_CODE(UNDEFINED_CMD);
}

/**
 * is_subtest_passed() - Return if a subtest passed
 * @thr: Thread data
 * @id: Subtest id
 *
 * Return:
 * PASSED          - Subtest passed
 * -FAILED         - Subtest failed
 * -INTERNAL       - Internal error if subtest id out of range
 */
static int is_subtest_passed(struct thread_data *thr, int id)
{
	int res = ERR_CODE(INTERNAL);

	if (id && id < thr->stat.number) {
		res = thr->stat.status_array[id - 1];
		if (res != ERR_CODE(PASSED))
			res = ERR_CODE(FAILED);
	}

	return res;
}

/**
 * run_subtest_vs_depends() - Check if subtest can be run vs its dependency.
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
static int run_subtest_vs_depends(struct thread_data *thr,
				  struct json_object *def)
{
	int res = ERR_CODE(PASSED);
	int dep_id = 0;
	size_t nb_members = 0;
	size_t i = 0;
	struct json_object *depends_obj = NULL;
	struct json_object *oval = NULL;

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

		for (; i < nb_members; i++) {
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
 */
static void run_subtest(struct thread_data *thr)
{
	int res = ERR_CODE(FAILED);
	char *cmd_name = NULL;
	const char *sub_used = NULL;
	const char *sub_exp = NULL;
	const char *exp_res_st = NULL;
	int exp_status = 0;
	struct subtest_data *subtest = NULL;

	subtest = thr->subtest;
	subtest->api_status = 0;
	subtest->api = "SMW";

	/* Verify the type of the subtest tag/value is json object */
	if (json_object_get_type(subtest->params) != json_type_object) {
		FPRINT_MESSAGE(thr->app, "Error in test definiton file: ");
		FPRINT_MESSAGE(thr->app,
			       "\"subtest\" is not a json-c object\n");
		DBG_PRINT("\"subtest\" is not a json-c object");

		res = ERR_CODE(BAD_PARAM_TYPE);
		goto exit;
	}

	/* 'command' is a mandatory parameter */
	res = util_read_json_type(&cmd_name, CMD_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED)) {
		if (res == ERR_CODE(VALUE_NOTFOUND)) {
			DBG_PRINT_MISS_PARAM(CMD_OBJ);
			res = ERR_CODE(MISSING_PARAMS);
		}

		goto exit;
	}

	res = util_read_json_type(&subtest->subsystem, SUBSYSTEM_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	res = util_read_json_type(&subtest->api, API_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Check dependent subtest(s) status */
	res = run_subtest_vs_depends(thr, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Get expected result parameter 'result' set in test definition file.
	 * If not defined, the default value is SMW_STATUS_OK.
	 */
	res = util_read_json_type(&exp_res_st, RES_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	if (exp_res_st) {
		res = get_int_status(&exp_status, exp_res_st, subtest->api);

		if (res != ERR_CODE(PASSED))
			goto exit;
	}

	/*
	 * Get SMW API version.
	 * If not set in test definition file, use default value.
	 */
	subtest->version = SMW_API_DEFAULT_VERSION;
	res = util_read_json_type(&subtest->version, VERSION_OBJ, t_int8,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/*
	 * Get expected subsystem to be used.
	 * If not set in test definition file don't verify it.
	 */
	res = util_read_json_type(&sub_exp, SUBSYSTEM_EXP_OBJ, t_string,
				  subtest->params);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
		goto exit;

	/* Wait semaphore */
	res = util_sem_wait_before(thr, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * In case of multi-application, post semaphores to
	 * application(s).
	 */
	res = util_sem_post_to_before(thr->app, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Post semaphore */
	res = util_sem_post_before(thr, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Execute subtest command */
	res = execute_command(cmd_name, subtest);

	if (util_check_result(subtest, exp_status)) {
		if (res == ERR_CODE(PASSED))
			res = ERR_CODE(FAILED);
	} else if (res == ERR_CODE(API_STATUS_NOK)) {
		res = ERR_CODE(PASSED);
	}

	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Wait semaphore */
	res = util_sem_wait_after(thr, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/*
	 * In case of multi-application, post semaphores to
	 * application(s).
	 */
	res = util_sem_post_to_after(thr->app, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	/* Post semaphore */
	res = util_sem_post_after(thr, subtest->params);
	if (res != ERR_CODE(PASSED))
		goto exit;

	if (sub_exp) {
		sub_used = smw_osal_latest_subsystem_name();
		if (sub_used) {
			DBG_PRINT("Selected subsystem: %s", sub_used);
			if (strcmp(sub_used, sub_exp)) {
				DBG_PRINT("Expected subsystem: %s", sub_exp);
				res = ERR_CODE(BAD_SUBSYSTEM);
			}
		} else {
			DBG_PRINT("WARNING - subsystem cannot be verified!");
		}
	}

exit:
	*thr->subtest->status = res;

	if (res == ERR_CODE(PASSED)) {
		if (INC_OVERFLOW(thr->stat.passed, 1))
			thr->stat.passed = 0;
	}

	if (thr->status == ERR_CODE(PASSED))
		thr->status = res;

	util_thread_log(thr);
}

void *process_thread(void *arg)
{
	int err = ERR_CODE(BAD_ARGS);
	int total = 0;
	int nb_loops = 1;
	int idx_stat = 0;
	size_t status_array_size = 0;
	struct thread_data *thr = arg;
	struct json_object_iter obj = { 0 };
	struct subtest_data subtest = { 0 };

	if (!thr || !thr->def) {
		DBG_PRINT_BAD_ARGS();
		exit(ERR_CODE(BAD_ARGS));
	}

	thr->stat.status_array = NULL;
	thr->stat.number = 0;
	thr->stat.ran = 0;
	thr->stat.passed = 0;

	if (!json_object_get_object(thr->def)) {
		DBG_PRINT("Thread definition json_object_get_object error");
		thr->status = ERR_CODE(INTERNAL);
		goto exit;
	}

	/*
	 * Get the number of subtests defined and allocate the
	 * subtest status array.
	 */
	json_object_object_foreachC(thr->def, obj)
	{
		/* Count the JSON-C "subtest" objects, other tags are ignored */
		if (!strncmp(obj.key, SUBTEST_OBJ, strlen(SUBTEST_OBJ)))
			thr->stat.number++;
	}

	total = thr->stat.number;
	if (MUL_OVERFLOW(thr->stat.number, sizeof(*thr->stat.status_array),
			 &status_array_size)) {
		thr->status = ERR_CODE(INTERNAL);
		goto exit;
	}

	thr->stat.status_array = malloc(status_array_size);
	if (!thr->stat.status_array) {
		DBG_PRINT_ALLOC_FAILURE();
		thr->status = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	thr->state = STATE_RUNNING;
	thr->status = ERR_CODE(PASSED);

	/* Wait semaphore if multi-thread test */
	err = util_sem_wait_before(thr, thr->parent_def);
	if (err != ERR_CODE(PASSED)) {
		thr->status = err;
		goto exit;
	}

	/*
	 * In case of multi-application, post semaphores to
	 * application(s).
	 */
	if (thr->parent_def) {
		err = util_sem_post_to_before(thr->app, thr->parent_def);
		if (err != ERR_CODE(PASSED)) {
			thr->status = err;
			goto exit;
		}
	}

	/* Post semaphore if multi-thread test */
	err = util_sem_post_before(thr, thr->parent_def);
	if (err != ERR_CODE(PASSED)) {
		thr->status = err;
		goto exit;
	}

	if (thr->loop) {
		nb_loops = thr->loop;
		total *= thr->loop;
	}

	thr->subtest = &subtest;

	for (; nb_loops; nb_loops--) {
		for (idx_stat = 0; idx_stat < thr->stat.number; idx_stat++)
			thr->stat.status_array[idx_stat] = ERR_CODE(FAILED);

		idx_stat = 0;
		json_object_object_foreachC(thr->def, obj)
		{
			/* Run the JSON-C "subtest" object, other tag is ignored */
			if (strncmp(obj.key, SUBTEST_OBJ, strlen(SUBTEST_OBJ)))
				continue;

			/* Reset the subtest data */
			memset(&subtest, 0, sizeof(subtest));

			subtest.app = thr->app;
			subtest.name = obj.key;
			subtest.params = obj.val;
			subtest.status = &thr->stat.status_array[idx_stat];
			if (INC_OVERFLOW(idx_stat, 1)) {
				err = ERR_CODE(INTERNAL);
				goto exit;
			}

			thr->stat.ran++;
			run_subtest(thr);
		}
	}

	thr->subtest = NULL;

	/* If no subtests ran - Failure */
	if (!thr->stat.ran || thr->stat.ran != total)
		thr->status = ERR_CODE(FAILED);

	/* Wait semaphore if multi-thread test */
	err = util_sem_wait_after(thr, thr->parent_def);
	if (err != ERR_CODE(PASSED))
		goto exit;

	/*
	 * In case of multi-application, post semaphores to
	 * application(s).
	 */
	if (thr->parent_def) {
		err = util_sem_post_to_after(thr->app, thr->parent_def);
		if (err != ERR_CODE(PASSED)) {
			thr->status = err;
			goto exit;
		}
	}

	/* Post semaphore if multi-thread test */
	err = util_sem_post_after(thr, thr->parent_def);

exit:
	thr->state = STATE_EXITED;

	if (thr->status == ERR_CODE(PASSED))
		thr->status = err;

	util_thread_log(thr);

	/* Decrement (free) the thread JSON-C definition */
	if (thr->def)
		json_object_put(thr->def);

	if (thr->stat.status_array) {
		free(thr->stat.status_array);
		thr->stat.status_array = NULL;
	}

	return &thr->status;
}
