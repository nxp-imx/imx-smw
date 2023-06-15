/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "types.h"

/**
 * cipher_psa() - Do a cipher one-shot operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_psa(struct subtest_data *subtest);

#endif /* __CIPHER_H__ */
