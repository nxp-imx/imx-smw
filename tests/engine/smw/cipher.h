/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "types.h"

/**
 * cipher() - Do a cipher one-shot operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher(struct subtest_data *subtest);

/**
 * cipher_init() - Do a cipher initialization
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_init(struct subtest_data *subtest);

/**
 * cipher_update() - Do a cipher update
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_update(struct subtest_data *subtest);

/**
 * cipher_final() - Do a cipher final
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_final(struct subtest_data *subtest);

#endif /* __CIPHER_H__ */
