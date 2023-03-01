/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __RNG_H__
#define __RNG_H__

#include "types.h"

/**
 * rng_psa() - Do a RNG operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * -SUBSYSTEM                   - RNG operation failed.
 * -BAD_PARAM_TYPE              - A parameter value is undefined.
 * Error code from util_read_hex_buffer().
 * Error code from set_rng_bad_args().
 */
int rng_psa(struct subtest_data *subtest);

#endif /* __RNG_H__ */
