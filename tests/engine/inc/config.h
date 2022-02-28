/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef __CONFIG_H__
#define __CONFIG_H__

#include "types.h"

/**
 * config_load() - Call configuration load API.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 * Error code from util_read_hex_buffer().
 */
int config_load(struct subtest_data *subtest);

/**
 * config_unload() - Call configuration unload API.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -API_STATUS_NOK          - SMW API Call return error
 */
int config_unload(struct subtest_data *subtest);

#endif /* __CONFIG_H__ */
