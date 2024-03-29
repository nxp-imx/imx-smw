/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2023 NXP
 */

#ifndef __HASH_H__
#define __HASH_H__

#include "types.h"

/**
 * get_hash_digest_len() - Return digest byte length switch algorithm.
 * @algo: Algorithm name.
 * @len: Pointer to digest length to update. Set to 0 if @algo is not found
 *       in @hash_size.
 *
 * Call this function with an undefined algo value is not an error.
 *
 * Return:
 * PASSED	- Success.
 * -BAD_ARGS	- One of the arguments is bad.
 */
int get_hash_digest_len(const char *algo, unsigned int *len);

/**
 * hash() - Do a hash operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Hash operation failed (bad hash digest).
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * Error code from util_read_hex_buffer().
 * Error code from get_hash_digest_len().
 * Error code from set_hash_bad_args().
 */
int hash(struct subtest_data *subtest);

#endif /* __HASH_H__ */
