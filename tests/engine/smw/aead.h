/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */

#ifndef __AEAD_H__
#define __AEAD_H__

#include "types.h"

/**
 * aead_get_mode_name() - Convert AEAD mode string value into integer value.
 * @string: AEAD mode string.
 *
 * Return:
 * AEAD mode name.
 */
smw_aead_mode_t aead_get_mode_name(const char *string);

/**
 * aead() - Execute AEAD one-shot operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int aead(struct subtest_data *subtest);

/**
 * aead_init() - Execute AEAD initialization operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int aead_init(struct subtest_data *subtest);

/**
 * aead_update_aad() - Execute AEAD update aad operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int aead_update_aad(struct subtest_data *subtest);

/**
 * aead_update() - Execute AEAD update operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int aead_update(struct subtest_data *subtest);

/**
 * aead_final() - Execute AEAD final operation
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -MISSING_PARAMS          - Missing mandatory parameters in @params.
 * -API_STATUS_NOK          - SMW API Call return error
 * -BAD_ARGS                - One of the arguments is bad.
 */
int aead_final(struct subtest_data *subtest);

#endif /* __AEAD_H__ */
