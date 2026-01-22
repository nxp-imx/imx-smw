/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024, 2026 NXP
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
 */
int hash_psa(struct subtest_data *subtest);

/**
 * hash_init_psa() - Do a hash init operation.
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
 */
int hash_init_psa(struct subtest_data *subtest);

/**
 * hash_update_psa() - Do a hash update operation.
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
 */
int hash_update_psa(struct subtest_data *subtest);

/**
 * hash_final_psa() - Do a hash final operation.
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
 */
int hash_final_psa(struct subtest_data *subtest);

/**
 * hash_verify_psa() - Do a hash verify operation.
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
 */
int hash_verify_psa(struct subtest_data *subtest);

/**
 * hash_clone_psa() - Do a hash clone operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Hash operation failed (bad hash digest).
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
int hash_clone_psa(struct subtest_data *subtest);

/**
 * hash_abort_psa() - Abort a hash multipart operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Hash operation failed (bad hash digest).
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 */
int hash_abort_psa(struct subtest_data *subtest);

#endif /* __HASH_H__ */
