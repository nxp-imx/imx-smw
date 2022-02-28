// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021-2022 NXP
 */

#include <string.h>

#include <smw_info.h>

#include "info.h"
#include "util.h"

static int check_version(struct subtest_data *subtest)
{
	int ret;
	unsigned int major = 255;
	unsigned int minor = 255;
	double exp_version = 0;
	double lib_version = 0;

	subtest->smw_status = smw_get_version(&major, &minor);
	if (subtest->smw_status != SMW_STATUS_OK)
		return ERR_CODE(API_STATUS_NOK);

	ret = util_read_json_type(&exp_version, LIB_VERSION_OBJ, t_double,
				  subtest->params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	DBG_PRINT("Library version is %d.%d", major, minor);

	/* Build the major.minor version double word */
	lib_version = minor;

	do {
		lib_version /= 10;
	} while ((int)lib_version);

	lib_version += major;

	if (exp_version != lib_version) {
		DBG_PRINT("Library expected version %f but get %f", exp_version,
			  lib_version);
		ret = ERR_CODE(FAILED);
	}

	return ret;
}

int get_info(struct subtest_data *subtest)
{
	int ret;
	enum arguments_test_err_case error = NOT_DEFINED;

	if (!subtest) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_read_test_error(&error, subtest->params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		ret = check_version(subtest);
		break;

	case ARGS_NULL:
		subtest->smw_status = smw_get_version(NULL, NULL);
		if (subtest->smw_status != SMW_STATUS_OK)
			ret = ERR_CODE(API_STATUS_NOK);
		break;

	default:
		DBG_PRINT_BAD_PARAM(TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	return ret;
}
