// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include <string.h>
#include <smw_info.h>

#include "info.h"
#include "json_types.h"
#include "util.h"

static int check_version(struct json_object *params,
			 enum smw_status_code *ret_status)
{
	int ret;
	unsigned int major = 255;
	unsigned int minor = 255;
	double exp_version = 0;
	double lib_version = 0;

	*ret_status = smw_get_version(&major, &minor);

	ret = util_read_json_type(&exp_version, LIB_VERSION_OBJ, t_double,
				  params);
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

int get_info(json_object *params, struct common_parameters *common_params,
	     enum smw_status_code *ret_status)
{
	int ret;
	enum arguments_test_err_case error;

	if (!params || !ret_status || !common_params) {
		DBG_PRINT_BAD_ARGS(__func__);
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_read_test_error(&error, params);
	if (ret != ERR_CODE(PASSED))
		return ret;

	switch (error) {
	case NOT_DEFINED:
		ret = check_version(params, ret_status);
		break;

	case ARGS_NULL:
		*ret_status = smw_get_version(NULL, NULL);
		break;

	default:
		DBG_PRINT_BAD_PARAM(__func__, TEST_ERR_OBJ);
		ret = ERR_CODE(BAD_PARAM_TYPE);
	}

	if (ret == ERR_CODE(PASSED) &&
	    CHECK_RESULT(*ret_status, common_params->expected_res))
		ret = ERR_CODE(BAD_RESULT);

	return ret;
}
