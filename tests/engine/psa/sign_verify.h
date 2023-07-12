/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __SIGN_VERIFY_H__
#define __SIGN_VERIFY_H__

#include "types.h"

#define SIGN_OPERATION	 0
#define VERIFY_OPERATION 1

/**
 * sign_verify() - Do a sign or verify operation.
 * @subtest: Subtest data.
 * @operation: SIGN_OPERATION or VERIFY_OPERATION
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * -SUBSYSTEM                   - Sign or verify operation failed.
 * -BAD_PARAM_TYPE              - A parameter value is undefined.
 * -MISSING_PARAMS              - Missing parameter in the test definition file.
 * -UNDEFINED_CMD               - Command is neither Sign nor Verify
 * Error code from key_desc_init().
 * Error code from key_read_descriptor().
 * Error code from util_read_hex_buffer().
 * Error code from util_sign_find_node().
 * Error code from set_sign_verify_bad_args().
 * Error code from util_sign_add_node().
 */
int sign_verify_psa(struct subtest_data *subtest, int operation);

#endif /* __SIGN_VERIFY_H__ */
