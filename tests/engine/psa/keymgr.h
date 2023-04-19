/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __KEYMGR_H__
#define __KEYMGR_H__

#include "json_types.h"
#include "types.h"

/**
 * generate_key_psa() - Generate a key.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -MISSING_PARAMS              - Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * Error code from get_test_err_status().
 * Error code from set_gen_bad_args().
 * Error code from set_gen_opt_params().
 * Error code from util_key_add_node().
 */
int generate_key_psa(struct subtest_data *subtest);

/**
 * delete_key_psa() - Delete a key.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -MISSING_PARAMS              - Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * Error code from get_test_err_status().
 * Error code from set_del_bad_args().
 */
int delete_key_psa(struct subtest_data *subtest);

/**
 * import_key_psa() - Import a key.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -MISSING_PARAMS              - Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * Error code from get_test_err_status().
 * Error code from set_import_bad_args().
 * Error code from set_import_opt_params().
 * Error code from util_key_add_node().
 */
int import_key_psa(struct subtest_data *subtest);

/**
 * export_key_psa() - Export a key.
 * @subtest: Subtest data.
 * @export_type: Type of key to export (private, public. keypair).
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -MISSING_PARAMS              - Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * -SUBSYSTEM                   - Expected exported key is wrong.
 * Error code from get_test_err_status().
 * Error code from set_export_bad_args().
 * Error code from set_import_opt_params().
 */
int export_key_psa(struct subtest_data *subtest, enum export_type export_type);

/**
 * get_key_attributes_psa() - Get the key attributes.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -MISSING_PARAMS              - Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 */
int get_key_attributes_psa(struct subtest_data *subtest);

#endif /* __KEYMGR_H__ */
