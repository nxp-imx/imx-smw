/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __SIGN_VERIFY_H__
#define __SIGN_VERIFY_H__

#include "json_types.h"
#include "util_sign.h"

#define SIGN_OPERATION	 0
#define VERIFY_OPERATION 1

/**
 * sign_verify() - Do a sign or verify operation.
 * @operation: SIGN_OPERATION or VERIFY_OPERATION
 * @params: Sign or verify parameters.
 * @common_params: Common commands parameters.
 * @algo_name: Hash algorithm name.
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   is saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Sign or verify operation failed.
 * -BAD_PARAM_TYPE		- A parameter value is undefined.
 * -MISSING_PARAMS		- Missing parameter in the test definition file.
 * -UNDEFINED_CMD		- Command is neither Sign nor Verify
 * Error code from util_key_desc_init().
 * Error code from util_key_read_descriptor().
 * Error code from util_key_find_key_node().
 * Error code from util_read_hex_buffer().
 * Error code from util_sign_find_node().
 * Error code from set_sign_verify_bad_args().
 * Error code from util_sign_add_node().
 */
int sign_verify(int operation, json_object *params,
		struct common_parameters *common_params, char *algo_name,
		struct key_identifier_list *key_identifiers,
		enum smw_status_code *ret_status);

/**
 * sign_clear_signatures_list() - Clear the signatures list.
 */
void sign_clear_signatures_list(void);

#endif /* __SIGN_VERIFY_H__ */
