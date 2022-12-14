/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __MAC_H__
#define __MAC_H__

#include "types.h"

/**
 * mac() - Do a MAC operation.
 * @subtest: Subtest data.
 * @verify: Set to true if MAC verification operation
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Cipher MAC operation failed.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
int mac(struct subtest_data *subtest, bool verify);

#endif /* __MAC_H__ */
