/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __DERIVE_H__
#define __DERIVE_H__

#include "types.h"

/**
 * derive_psa() - Execute a derive operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Function failed.
 * -BAD_PARAM_TYPE          - A parameter value is undefined.
 */
int derive_psa(struct subtest_data *subtest);

#endif /* __DERIVE_H__ */
