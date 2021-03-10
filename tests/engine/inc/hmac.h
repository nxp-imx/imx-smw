/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __HMAC_H__
#define __HMAC_H__

/**
 * hmac() - Do a HMAC operation.
 * @params: HMAC parameters.
 * @common_params: Common commands parameters.
 * @algo_name: HMAC algorithm name.
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   is saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_RESULT			- SMW API status differs from expected one.
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
int hmac(json_object *params, struct common_parameters *common_params,
	 char *algo_name, struct key_identifier_list *key_identifiers,
	 int *ret_status);

#endif /* __HMAC_H__ */
