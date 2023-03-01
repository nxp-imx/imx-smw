/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2023 NXP
 */

#ifndef __OPERATION_CONTEXT_H__
#define __OPERATION_CONTEXT_H__

#include "types.h"

/**
 * cancel_operation() - Cancel operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED
 * -BAD_ARGS               - One of the arguments is bad
 * -BAD_PARAM_TYPE         - A parameter value is undefined.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params
 * -API_STATUS_NOK         - SMW API Call return error
 * -FAILED                 - Operation context is not found
 */
int cancel_operation(struct subtest_data *subtest);

/**
 * copy_context() - Copy operation context
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                  - Success
 * -BAD_ARGS               - One of the arguments is bad
 * -BAD_PARAM_TYPE         - A parameter value is undefined.
 * -MISSING_PARAMS         - Missing mandatory parameters in @params
 * -API_STATUS_NOK         - SMW API Call return error
 * -FAILED                 - Operation context is not found
 * -INTERNAL_OUT_OF_MEMORY - Memory allocation failed
 * -INTERNAL               - Internal error
 */
int copy_context(struct subtest_data *subtest);

#endif /* __OPERATION_CONTEXT_H__ */
