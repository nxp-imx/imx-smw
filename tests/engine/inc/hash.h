/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2022 NXP
 */

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

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
int get_hash_digest_len(char *algo, unsigned int *len);

/**
 * hash() - Do a hash operation.
 * @params: Hash parameters.
 * @cmn_params: Some parameters common to commands.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Hash operation failed (bad hash digest).
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * Error code from util_read_hex_buffer().
 * Error code from get_hash_digest_len().
 * Error code from set_hash_bad_args().
 */
int hash(json_object *params, struct cmn_params *cmn_params,
	 enum smw_status_code *ret_status);

#endif /* __CRYPTO_H__ */
