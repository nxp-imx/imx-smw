// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include <json.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smw_osal.h"

#include "util.h"
#include "util_file.h"
#include "util_log.h"
#include "util_thread.h"
#include "paths.h"
#include "run_thread.h"

static const struct tee_info tee_default_info = {
	{ "11b5c4aa-6d20-11ea-bc55-0242ac130003" }
};

static const struct se_info se_default_info = { 0x534d5754, 0x444546,
						1000 }; // SMWT, DEF

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

	res = setup_tee_info(app->definition);
	if (res != ERR_CODE(PASSED))
		goto end;

	res = setup_hsm_info(app->definition);
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
 * -FAILED - Subtest failed
 */
static int run_multithread(struct app_data *app)
{
	int status = ERR_CODE(PASSED);
	int res;
	struct json_object_iter obj;
	unsigned int thr_counter = 1;
	unsigned int first, last;

	if (!app || !app->definition)
		return ERR_CODE(FAILED);

	if (!json_object_get_object(app->definition))
		return ERR_CODE(FAILED);

	app->is_multithread = 1;

	json_object_object_foreachC(app->definition, obj)
	{
		first = 0;
		last = 0;

		/* Run the JSON-C "Thread" object, other tag is ignored */
		if (strncmp(obj.key, THREAD_OBJ, strlen(THREAD_OBJ)))
			continue;

		/* Get Thread ID */
		res = util_thread_get_ids(obj.key, &first, &last);
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

	res = util_thread_end(app);
	status = (status == ERR_CODE(PASSED)) ? res : status;

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
 * -FAILED - Single Thread test failed
 */
static int run_singlethread(struct app_data *app)
{
	int *status;
	struct thread_data thr = { 0 };

	if (!app || !app->definition)
		return ERR_CODE(FAILED);

	thr.app = app;

	/*
	 * Increment reference to application test definition
	 * the process_thread call json_object_put() regardless
	 * if it's a thread test or not.
	 */
	thr.def = json_object_get(app->definition);

	status = process_thread(&thr);

	return *status;
}

/*
 * List of the tests type function of the test definition top tag/value.
 * The subsystem definition defined with the tag "TEE_INFO_OBJ" and
 * "HSM_INFO_OBJ" are ignored.
 */
const struct test_type {
	const char *name;
	int (*run)(struct app_data *app);
} test_types[] = { { TEE_INFO_OBJ, NULL },
		   { HSM_INFO_OBJ, NULL },
		   { SUBTEST_OBJ, &run_singlethread },
		   { THREAD_OBJ, &run_multithread },
		   { NULL, NULL } };

/**
 * get_test_type() - Get the test type to run
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
static const struct test_type *get_test_type(struct app_data *app)
{
	const struct test_type *test;
	struct json_object_iter obj;

	if (!app || !app->definition)
		return NULL;

	if (!json_object_get_object(app->definition))
		return NULL;

	json_object_object_foreachC(app->definition, obj)
	{
		for (test = test_types; test->name; test++) {
			if (!strncmp(obj.key, test->name, strlen(test->name))) {
				if (!test->run)
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

/**
 * run_test() - Run a test.
 * @def_file: Name of the test definition file.
 * @test_name: Test name.
 * @output_dir: Path to output test status directory. If NULL, the default
 *              path DEFAULT_OUT_STATUS_PATH is used.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL			- Internal error.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_ARGS			- One of the arguments is bad.
 */
static int run_test(char *def_file, char *test_name, char *output_dir)
{
	int test_status = ERR_CODE(FAILED);
	int err;
	char *dir = output_dir;
	char *name = NULL;
	const struct test_type *test;
	struct app_data *app;

	app = util_setup_app();
	if (!app)
		return ERR_CODE(INTERNAL);

	if (!def_file || !test_name) {
		DBG_PRINT_BAD_ARGS();
		test_status = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	if (!dir)
		dir = DEFAULT_OUT_STATUS_PATH;

	name = malloc(strlen(test_name) + strlen(TEST_STATUS_EXTENSION) + 1);
	if (!name) {
		DBG_PRINT_ALLOC_FAILURE();
		test_status = ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		goto exit;
	}

	strcpy(name, test_name);
	strcat(name, TEST_STATUS_EXTENSION);

	test_status = util_file_open(dir, name, "w+", &app->log);
	if (test_status != ERR_CODE(PASSED))
		goto exit;

	test_status = util_read_json_file(NULL, def_file, &app->definition);
	if (test_status != ERR_CODE(PASSED)) {
		FPRINT_TEST_INTERNAL_FAILURE(app, test_name);
		goto exit;
	}

	/* Free the file name no more used */
	free(name);
	name = NULL;

	/* Get the test definition folder path */
	app->dir_def_file = dirname(def_file);

	test_status = init_smwlib(app);
	if (test_status != ERR_CODE(PASSED))
		goto exit;

	/*
	 * Check from test name if it's a test to verify the API only
	 */
	if (strstr(test_name, TEST_API_TYPE))
		app->is_api_test = 1;

	test = get_test_type(app);

	if (test)
		test_status = test->run(app);

exit:
	if (name)
		free(name);

	if (test_status == ERR_CODE(PASSED))
		FPRINT_TEST_STATUS(app, test_name, ERR_STATUS(PASSED));
	else
		FPRINT_TEST_STATUS(app, test_name, ERR_STATUS(FAILED));

	err = util_destroy_app();
	if (test_status == ERR_CODE(PASSED))
		test_status = err;

	return test_status;
}

/**
 * usage - Print program usage.
 * @progname: Program name.
 *
 * Return:
 * None.
 */
static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("\n");
	printf("options:\n");
	printf("\t-h    This help\n");
	printf("\t-d    Definition test file\n");
	printf("\t-o    Path to output test status directory\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int res = ERR_CODE(BAD_ARGS);
	int option = 0;
	char *def_file = NULL;
	char *test_name = NULL;
	char *output_dir = NULL;

	if (argc > 1) {
		/*
		 * Parse command line argument to get the
		 * option of the test execution.
		 * If one of the option is unknown exit in error.
		 */
		do {
			option = getopt(argc, argv, "hd:o:");

			switch (option) {
			case -1:
				break;

			case 'd':
				def_file = optarg;
				break;

			case 'o':
				output_dir = optarg;
				break;

			case 'h':
				usage(argv[0]);
				return 0;

			default:
				usage(argv[0]);
				return res;
			}
		} while (option != -1);
	} else {
		usage(argv[0]);
		return res;
	}

	res = get_test_name(&test_name, def_file);
	if (res != ERR_CODE(PASSED))
		goto exit;

	res = run_test(def_file, test_name, output_dir);

exit:
	if (test_name)
		free(test_name);

	return res;
}
