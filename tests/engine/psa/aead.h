/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef __AEAD_H__
#define __AEAD_H__

#include "types.h"

/**
 * aead_encrypt_psa() - Do a cipher one-shot operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_psa(struct subtest_data *subtest);

#endif /* __AEAD_H__ */
