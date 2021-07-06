/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef __KEYMGR_H__
#define __KEYMGR_H__

#include "json_types.h"
#include "types.h"
#include "util_key.h"

/**
 * generate_key() - Generate a key.
 * @params: Generate key parameters.
 * @common_params: Some parameters common to commands.
 * @key_type: Type of key to generate.
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   will be saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * Error code from get_test_err_status().
 * Error code from set_gen_bad_args().
 * Error code from set_gen_opt_params().
 * Error code from key_identifier_add_list().
 */
int generate_key(json_object *params, struct common_parameters *common_params,
		 char *key_type, struct key_identifier_list **key_identifiers,
		 enum smw_status_code *ret_status);

/**
 * delete_key() - Delete a key.
 * @params: Delete key parameters.
 * @common_params: Some parameters common to commands.
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   is saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED		- Success.
 * -MISSING_PARAMS	- Missing mandatory parameters in @params.
 * -BAD_RESULT		- SMW API status differs from expected one.
 * -BAD_ARGS		- One of the arguments is bad.
 * Error code from get_test_err_status().
 * Error code from set_del_bad_args().
 */
int delete_key(json_object *params, struct common_parameters *common_params,
	       struct key_identifier_list *key_identifiers,
	       enum smw_status_code *ret_status);

/**
 * import_key() - Import a key.
 * @params: Import key parameters.
 * @common_params: Some parameters common to commands.
 * @key_type: Type of key to import.
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   will be saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * Error code from get_test_err_status().
 * Error code from set_import_bad_args().
 * Error code from set_import_opt_params().
 * Error code from key_identifier_add_list().
 */
int import_key(json_object *params, struct common_parameters *common_params,
	       char *key_type, struct key_identifier_list **key_identifiers,
	       enum smw_status_code *ret_status);

/**
 * export_key() - Export a key.
 * @params: Import key parameters.
 * @common_params: Some parameters common to commands.
 * @export_type: Type of key to export (private, public. keypair).
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   will be saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 * -SUBSYSTEM			- Expected exported key is wrong.
 * Error code from get_test_err_status().
 * Error code from set_export_bad_args().
 * Error code from set_import_opt_params().
 */
int export_key(json_object *params, struct common_parameters *common_params,
	       enum export_type export_type,
	       struct key_identifier_list *key_identifiers,
	       enum smw_status_code *ret_status);

/**
 * derive_key() - Derive a key.
 * @params: Derive key parameters.
 * @common_params: Some parameters common to commands.
 * @key_identifiers: Key identifier linked list where key identifier value
 *                   will be saved.
 * @ret_status: Status returned by SMW API.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -BAD_RESULT			- SMW API status differs from expected one.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int derive_key(json_object *params, struct common_parameters *common_params,
	       struct key_identifier_list **key_identifiers,
	       enum smw_status_code *ret_status);

#endif /* __KEYMGR_H__ */
