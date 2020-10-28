/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

/**
 * hash() - Do a hash operation.
 * @params: Hash parameters.
 * @common_params: Some parameters common to commands.
 * @algo_type: Algorithm used.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Hash operation failed (bad hash digest).
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * Error code from get_test_err_status().
 * Error code from convert_string_to_hex().
 * Error code from get_hash_digest_len().
 */
int hash(json_object *params, struct common_parameters *common_params,
	 char *algo_type, int *ret_status);

#endif /* __CRYPTO_H__ */
