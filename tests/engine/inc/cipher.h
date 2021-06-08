/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

/**
 * cipher() - Do a cipher one-shot operation
 * @params: JSON Cipher parameters.
 * @common_params: Common commands parameters.
 * @key_identifiers: Key identifier linked list.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher(struct json_object *params, struct common_parameters *common_params,
	   struct key_identifier_list *key_identifiers, int *ret_status);

/**
 * cipher_init() - Do a cipher initialization
 * @params: JSON Cipher parameters.
 * @common_params: Common commands parameters.
 * @key_identifiers: Key identifier linked list.
 * @ctx: Context linked list.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_init(struct json_object *params,
		struct common_parameters *common_params,
		struct key_identifier_list *key_identifiers,
		struct context_list **ctx, int *ret_status);

/**
 * cipher_update() - Do a cipher update
 * @params: JSON Cipher parameters.
 * @common_params: Common commands parameters.
 * @ctx: Context linked list.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_update(struct json_object *params,
		  struct common_parameters *common_params,
		  struct context_list *ctx, int *ret_status);

/**
 * cipher_final() - Do a cipher final
 * @params: JSON Cipher parameters.
 * @common_params: Common commands parameters.
 * @ctx: Context linked list.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_final(struct json_object *params,
		 struct common_parameters *common_params,
		 struct context_list *ctx, int *ret_status);

/**
 * cipher_clear_out_data_list() - Clear cipher output data linked list
 *
 * Return:
 * none
 */
void cipher_clear_out_data_list(void);

#endif /* __CIPHER_H__ */