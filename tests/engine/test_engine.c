// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <json.h>
#include <libgen.h>
#include <string.h>

#include "util.h"
#include "util_file.h"
#include "util_log.h"
#include "paths.h"
#include "run_app.h"

static int run_singleapp(struct test_data *test);
static int run_multiapp(struct test_data *test);

/*
 * List of the application type function of the test definition top tag/value.
 * The subsystem definition defined with the tag "TEE_INFO_OBJ" and
 * "HSM_INFO_OBJ" are ignored.
 */
const struct app_type {
	const char *name;
	int (*run_app)(struct test_data *test);
} app_types[] = {
	{ TEE_INFO_OBJ, NULL },		{ HSM_INFO_OBJ, NULL },
	{ APP_OBJ, &run_multiapp },	{ SUBTEST_OBJ, &run_singleapp },
	{ THREAD_OBJ, &run_singleapp }, { NULL, NULL }
};

/**
 * run_singleapp() - Run a single application test
 * @test_data: Overall test data
 *
 * Return
 * PASSED  - Application test passed
 * or any error code (see enum err_num)
 */
static int run_singleapp(struct test_data *test)
{
	int status = ERR_CODE(FAILED);

	test->is_multi_apps = 0;
	test->nb_apps = 1;

	/*
	 * Create a single application in the test list.
	 * Application definition is the test input definition file.
	 */
	status = util_app_create(test, 1, test->definition);
	if (status == ERR_CODE(PASSED))
		status = run_apps(test);

	return status;
}

/**
 * run_multiapp() - Run a multiple application test
 * @test: Overall test data
 *
 * Return
 * PASSED  - All applications test passed
 * or any error code (see enum err_num)
 */
static int run_multiapp(struct test_data *test)
{
	int status = ERR_CODE(FAILED);
	int res;
	struct json_object_iter obj;
	unsigned int app_counter = 1;
	unsigned int first, last;

	if (!json_object_get_object(test->definition)) {
		DBG_PRINT("Test definition json_object_get_object error");
		status = ERR_CODE(INTERNAL);
		goto exit;
	}

	test->is_multi_apps = 1;

	json_object_object_foreachC(test->definition, obj)
	{
		first = 0;
		last = 0;

		/* Get Application ID */
		status = util_get_json_obj_ids(obj.key, APP_OBJ, &first, &last);
		if (status != ERR_CODE(PASSED)) {
			status = ERR_CODE(FAILED);
			goto exit;
		}

		/*
		 * Check if the first application ID is the contiguous to the
		 * application counter.
		 */
		if (first != app_counter) {
			DBG_PRINT("\"%s\" first ID is not contiguous", obj.key);
			status = ERR_CODE(FAILED);
			goto exit;
		}

		for (; app_counter < last + 1; app_counter++) {
			status = util_app_create(test, app_counter, obj.val);
			if (status != ERR_CODE(PASSED))
				goto exit;
		}
	}

	test->nb_apps = app_counter - 1;

	status = run_apps(test);

	res = util_app_wait(test);
	status = (status == ERR_CODE(PASSED)) ? res : status;

exit:
	return status;
}

/**
 * get_app_type() - Get the test application type to run
 * @test: Overall test data
 *
 * Test definition can be either:
 *  - single or multiple application.
 *  - single or multiple thread.
 *
 * If the test object definition is to check application type:
 *  - "App xxx" tag goes to multiple application test
 *  - Else this is a single application test
 *
 * Return:
 * The test type object if found else NULL
 */
static const struct app_type *get_app_type(struct test_data *test_data)
{
	const struct app_type *test;
	struct json_object_iter obj;

	if (!test_data || !test_data->definition)
		return NULL;

	if (!json_object_get_object(test_data->definition))
		return NULL;

	json_object_object_foreachC(test_data->definition, obj)
	{
		for (test = app_types; test->name; test++) {
			if (!strncmp(obj.key, test->name, strlen(test->name))) {
				if (!test->run_app)
					break;

				return test;
			}
		}

		if (!test->name) {
			util_log(test_data, "JSON-C tag name %s ignored\n",
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
	char *dir = output_dir;
	char *name = NULL;
	struct test_data *test_data;
	const struct app_type *test;

	test_data = util_setup_test();
	if (!test_data)
		return ERR_CODE(INTERNAL);

	if (!def_file || !test_name) {
		DBG_PRINT_BAD_ARGS();
		test_status = ERR_CODE(BAD_ARGS);
		goto exit;
	}

	test_data->name = test_name;

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

	test_status = util_file_open(dir, name, "w+", &test_data->log);
	if (test_status != ERR_CODE(PASSED))
		goto exit;

	test_status =
		util_read_json_file(NULL, def_file, &test_data->definition);
	if (test_status != ERR_CODE(PASSED))
		goto exit;

	/* Get the test definition folder path */
	test_data->dir_def_file = dirname(def_file);

	/*
	 * Check from test name if it's a test to verify the API only
	 */
	if (strstr(test_name, TEST_API_TYPE))
		test_data->is_api_test = 1;

	/* Check if it's a single or multiple application */
	test = get_app_type(test_data);
	if (test)
		test_status = test->run_app(test_data);
	else
		test_status = ERR_CODE(FAILED);

exit:
	if (name)
		free(name);

	if (test_status == ERR_CODE(PASSED)) {
		util_log(test_data, "%s: %s\n", test_name,
			 util_get_err_code_str(test_status));
	} else {
		util_log(test_data, "%s: %s (%s)\n", test_name,
			 util_get_err_code_str(ERR_CODE(FAILED)),
			 util_get_err_code_str(test_status));
		test_status = ERR_CODE(FAILED);
	}

	util_destroy_test(test_data);

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
