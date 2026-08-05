/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023, 2026 NXP
 */

#ifndef __CIPHER_H__
#define __CIPHER_H__

#include "types.h"

/**
 * cipher_psa() - Do a cipher one-shot operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK		- SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_psa(struct subtest_data *subtest);

/**
 * cipher_init_psa() - Do a PSA cipher initialization
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int cipher_init_psa(struct subtest_data *subtest);

/**
 * cipher_set_iv_psa() - PSA cipher set initialization vector
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int cipher_set_iv_psa(struct subtest_data *subtest);

/**
 * cipher_generate_iv_psa() - PSA cipher generate initialization vector
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int cipher_generate_iv_psa(struct subtest_data *subtest);

/**
 * cipher_update_psa() - Do a PSA cipher update
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int cipher_update_psa(struct subtest_data *subtest);

/**
 * cipher_final_psa() - Do a PSA cipher final
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK		- SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_final_psa(struct subtest_data *subtest);

/**
 * cipher_abort_psa() - Do a PSA cipher abort
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK		- SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int cipher_abort_psa(struct subtest_data *subtest);

#endif /* __CIPHER_H__ */
