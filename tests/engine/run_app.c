// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <json.h>
#include <string.h>

#include "smw_osal.h"

#include "util.h"
#include "util_app.h"
#include "util_ipc.h"
#include "util_list.h"
#include "util_log.h"
#include "util_sem.h"
#include "util_thread.h"
#include "run_thread.h"

#define DEFAULT_KEY_DB "/var/tmp/key_db_smw_test.dat"

static const struct tee_info tee_default_info = {
	{ "11b5c4aa-6d20-11ea-bc55-0242ac130003" }
};

static const struct se_info se_default_info = { 0x534d5754, 0x444546,
						1000 }; // SMWT, DEF

static int run_singlethread(struct app_data *app);
static int run_multithread(struct app_data *app);

/*
 * List of the tests type function of the test definition top tag/value.
 * The subsystem definition defined with the tag "TEE_INFO_OBJ" and
 * "HSM_INFO_OBJ" are ignored.
 */
const struct thread_type {
	const char *name;
	int (*run_thread)(struct app_data *app);
} thread_types[] = { { TEE_INFO_OBJ, NULL },
		     { HSM_INFO_OBJ, NULL },
		     { SUBTEST_OBJ, &run_singlethread },
		     { THREAD_OBJ, &run_multithread },
		     { FILEPATH_OBJ, &run_multithread },
		     { NULL, NULL } };

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
 * setup_key_db() -  Open/Create the application key database
 * @test_def: JSON-C test definition of the application
 *
 * Return:
 * PASSED              - Success.
 * -BAD_PARAM_TYPE     - Parameter type is not correct or not supported.
 * -BAD_ARGS           - One of the argument is bad.
 * -FAILED             - Error in definition file
 * -ERROR_SMWLIB_INIT  - SMW Library initialization error
 */
static int setup_key_db(json_object *test_def)
{
	int res;
	char *filepath = DEFAULT_KEY_DB;
	json_object *oinfo = NULL;

	res = util_read_json_type(&oinfo, KEY_DB_OBJ, t_object, test_def);
	if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND) &&
	    !oinfo)
		return res;

	if (res == ERR_CODE(PASSED)) {
		res = util_read_json_type(&filepath, FILEPATH_OBJ, t_string,
					  oinfo);
		if (res != ERR_CODE(PASSED) && res != ERR_CODE(VALUE_NOTFOUND))
			return res;
	}

	res = smw_osal_open_key_db(filepath, strlen(filepath) + 1);
	if (res != SMW_STATUS_OK) {
		DBG_PRINT("SMW Create Key database failed %s",
			  get_smw_string_status(res));
		res = ERR_CODE(ERROR_SMWLIB_INIT);
	} else {
		res = ERR_CODE(PASSED);
	}

	return res;
}

/**
 * init_smwlib() - Initialize the SMW Library
 * @app: Application data object
 *
 * Function extracts from the test definition the application configuration
 * and call the SMW Library inilization API.
 *
 * Return:
 * PASSED              - Success.
 * -ERROR_SMWLIB_INIT  - SMW Library initialization error
 */
static int init_smwlib(struct app_data *app)
{
	int res;

	res = setup_tee_info(app->parent_def);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = setup_hsm_info(app->parent_def);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = setup_key_db(app->parent_def);
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
 * run_multithread() - Run a multi-thread test
 * @app: Application data
 *
 * Return
 * PASSED  - Success
 * or any error code (see enum err_num)
 */
static int run_multithread(struct app_data *app)
{
	int status = ERR_CODE(PASSED);
	int res;
	struct json_object_iter obj;
	unsigned int thr_counter = 1;
	unsigned int first, last;

	if (!app || !app->parent_def)
		return ERR_CODE(FAILED);

	status = util_get_subdef(&app->def, app->parent_def, app->test);
	if (status != ERR_CODE(PASSED))
		goto end;

	app->timeout = 10;
	app->is_multithread = 1;

	if (!json_object_get_object(app->def)) {
		status = ERR_CODE(FAILED);
		goto end;
	}

	json_object_object_foreachC(app->def, obj)
	{
		first = 0;
		last = 0;

		/* Run the JSON-C "Thread" object, other tag is ignored */
		if (strncmp(obj.key, THREAD_OBJ, strlen(THREAD_OBJ)))
			continue;

		/* Get Thread ID */
		res = util_get_json_obj_ids(obj.key, THREAD_OBJ, &first, &last);
		if (res != ERR_CODE(PASSED)) {
			status = ERR_CODE(FAILED);
			break;
		}

		/*
		 * Check if the first thread ID is the contiguous to the
		 * thread counter.
		 */
		if (first != thr_counter) {
			DBG_PRINT("\"%s\" first ID is not contiguous", obj.key);
			status = ERR_CODE(FAILED);
			break;
		}

		/* Create and start all threads */
		for (; thr_counter < last + 1; thr_counter++) {
			res = util_thread_start(app, &obj, thr_counter);
			status = (status == ERR_CODE(PASSED)) ? res : status;
		}
	}

	res = util_thread_ends_wait(app);

	status = (status == ERR_CODE(PASSED)) ? res : status;

end:
	if (app->def)
		json_object_put(app->def);

	return status;
}

/**
 * run_singlethread() - Run a single thread test
 * @app: Application data
 *
 * Execute a single thread test described with JSON-C "subtest" object.
 *
 * Return
 * PASSED  - Single Thread test passed
 * or any error code (see enum err_num)
 */
static int run_singlethread(struct app_data *app)
{
	int *status;
	struct thread_data thr = { 0 };

	if (!app || !app->parent_def)
		return ERR_CODE(FAILED);

	thr.app = app;

	/*
	 * Increment reference to application test definition
	 * the process_thread call json_object_put() regardless
	 * if it's a thread test or not.
	 */
	thr.def = json_object_get(app->parent_def);

	status = process_thread(&thr);

	return *status;
}

/**
 * get_thread_type() - Get the application thread type to run
 * @app: Application data
 *
 * Application test definition can be either single or multi threads.
 * If the application definition file top object(s) is(are) "subtest",
 * this is a single application/thread test.
 * Else if the top object(s) is(are) "Thread", this is a single
 * application with at least one thread.
 *
 * Return:
 * The test type object if found else NULL
 */
static const struct thread_type *get_thread_type(struct app_data *app)
{
	const struct thread_type *test;
	struct json_object_iter obj;

	if (!app || !app->parent_def)
		return NULL;

	if (!json_object_get_object(app->parent_def))
		return NULL;

	json_object_object_foreachC(app->parent_def, obj)
	{
		for (test = thread_types; test->name; test++) {
			if (!strncmp(obj.key, test->name, strlen(test->name))) {
				if (!test->run_thread)
					break;

				return test;
			}
		}

		if (!test->name) {
			FPRINT_MESSAGE(app, "JSON-C tag name %s ignored\n",
				       obj.key);
			DBG_PRINT("WARNING: JSON-C object tag %s ignored",
				  obj.key);
		}
	}

	return NULL;
}

int process_app(struct app_data *app)
{
	int status = ERR_CODE(FAILED);
	int err;
	const struct thread_type *thr;

	if (!app || !app->test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	app->pid = getpid();

	status = init_smwlib(app);
	if (status != ERR_CODE(PASSED))
		goto exit;

	thr = get_thread_type(app);
	if (!thr) {
		status = ERR_CODE(FAILED);
		goto exit;
	}

	if (app->test->is_multi_apps) {
		/* Start Thread waiting for IPC message */
		status = util_ipc_start(app);
		if (status != ERR_CODE(PASSED))
			goto exit;

		/*
		 * In case of multi-application, post semaphores to
		 * application(s).
		 */
		status = util_sem_post_to_before(app, app->parent_def);
		if (status != ERR_CODE(PASSED))
			goto exit;
	}

	status = thr->run_thread(app);

	if (app->test->is_multi_apps) {
		/*
		 * In case of multi-application, post semaphores to
		 * application(s).
		 */
		err = util_sem_post_to_after(app, app->parent_def);
		status = (status == ERR_CODE(PASSED)) ? err : status;
	}

exit:
	if (app->test->is_multi_apps)
		util_ipc_end(app);

	return status;
}

int run_apps(struct test_data *test)
{
	int status = ERR_CODE(PASSED);
	int res;
	int nb_apps = 0;
	struct node *node = NULL;
	struct app_data *app = NULL;

	if (!test || !test->apps) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	node = util_list_next(test->apps, node, NULL);
	while (node) {
		app = util_list_data(node);
		if (app) {
			nb_apps++;
			if (test->is_multi_apps)
				res = util_app_fork(app);
			else
				res = process_app(app);

			status = (status == ERR_CODE(PASSED)) ? res : status;
		}
		node = util_list_next(test->apps, node, NULL);
	};

	if (!nb_apps)
		status = ERR_CODE(FAILED);

	return status;
}
