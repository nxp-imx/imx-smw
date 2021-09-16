/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __INFO_H__
#define __INFO_H__

#include <json.h>
#include <smw_status.h>

#include "types.h"

/**
 * get_info() - Test get information API.
 * @params: Get information parameters.
 * @common_params: Common commands parameters.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED		- Success.
 * -BAD_RESULT		- SMW API status differs from expected one.
 * -BAD_ARGS		- One of the arguments is bad.
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 * -VALUE_NOTFOUND	- Test definition Value not found.
 * -FAILED		- Test failed
 */
int get_info(struct json_object *params,
	     struct common_parameters *common_params,
	     enum smw_status_code *ret_status);

#endif /* __INFO_H__ */
