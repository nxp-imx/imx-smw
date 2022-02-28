/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef __HMAC_H__
#define __HMAC_H__

#include "types.h"

/**
 * hmac() - Do a HMAC operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- HMAC operation failed.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * Error code from util_key_desc_init().
 * Error code from util_key_read_descriptor().
 * Error code from util_key_find_key_node().
 * Error code from util_read_hex_buffer().
 * Error code from get_hash_digest_len().
 * Error code from set_hmac_bad_args().
 */
int hmac(struct subtest_data *subtest);

#endif /* __HMAC_H__ */
