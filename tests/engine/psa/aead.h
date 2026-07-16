/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024, 2026 NXP
 */

#ifndef __AEAD_H__
#define __AEAD_H__

#include "types.h"

/**
 * aead_psa() - Do a one-shot AEAD operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_psa(struct subtest_data *subtest);

/**
 * aead_init_psa() - Set up a multi-part PSA AEAD operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_init_psa(struct subtest_data *subtest);

/**
 * aead_update_aad_psa() - Pass additional data to an active PSA AEAD operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_update_aad_psa(struct subtest_data *subtest);

/**
 * aead_update_psa() - Encrypt or decrypt a data fragment in an active PSA AEAD
 *                     operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_update_psa(struct subtest_data *subtest);

/**
 * aead_final_psa() - Finish a multi-part PSA AEAD operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -MISSING_PARAMS		- Missing mandatory parameters in @params.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_final_psa(struct subtest_data *subtest);

/**
 * aead_set_lengths_psa() - Set the plaintext and AAD lengths for a PSA AEAD
 *                          operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_set_lengths_psa(struct subtest_data *subtest);

/**
 * aead_set_nonce_psa() - Set or generate the nonce for a PSA AEAD operation
 * @subtest: Subtest data.
 *
 * When "iv" is a hex buffer, psa_aead_set_nonce() is called.
 * When "iv" is an integer or absent, psa_aead_generate_nonce() is called.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_set_nonce_psa(struct subtest_data *subtest);

/**
 * aead_abort_psa() - Abort a PSA AEAD operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED			- Success.
 * -INTERNAL_OUT_OF_MEMORY	- Memory allocation failed.
 * -API_STATUS_NOK		- PSA API call returned an error.
 * -BAD_ARGS			- One of the arguments is bad.
 */
int aead_abort_psa(struct subtest_data *subtest);

#endif /* __AEAD_H__ */
