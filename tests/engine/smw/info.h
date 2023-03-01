/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */

#ifndef __INFO_H__
#define __INFO_H__

#include "types.h"

/**
 * get_info() - Test get information API.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED		- Success.
 * -API_STATUS_NOK      - SMW API Call return error
 * -BAD_ARGS		- One of the arguments is bad.
 * -BAD_PARAM_TYPE	- A parameter value is undefined.
 * -VALUE_NOTFOUND	- Test definition Value not found.
 * -FAILED		- Test failed
 */
int get_info(struct subtest_data *subtest);

#endif /* __INFO_H__ */
