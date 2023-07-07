/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __HASH_H__
#define __HASH_H__

#include <psa/crypto_types.h>

#include "types.h"

/**
 * get_hash_alg_id() - Convert hash name in PSA Hash ID.
 * @alg_name: Hash name.
 *
 * Return:
 * PSA Hash ID, if @alg_name is known
 * -PSA_ALG_NONE
 */
psa_algorithm_t get_hash_alg_id(const char *alg_name);

/**
 * hash_psa() - Do a hash operation.
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
int hash_psa(struct subtest_data *subtest);

#endif /* __HASH_H__ */
