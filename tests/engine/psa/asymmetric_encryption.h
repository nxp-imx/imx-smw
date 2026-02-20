/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ASYMMETRIC_ENCRYPTION_H__
#define __ASYMMETRIC_ENCRYPTION_H__

#include "types.h"

/**
 * asymmetric_encrypt_decrypt_psa() - Perform asymmetric encryption operation.
 * @subtest: Subtest data.
 * @encryption_op: True, if encryption operation.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -MISSING_PARAMS              - Missing mandatory parameters in @params.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 */
int asymmetric_encrypt_decrypt_psa(struct subtest_data *subtest,
				   bool encryption_op);

#endif /* __ASYMMETRIC_ENCRYPTION_H__ */
