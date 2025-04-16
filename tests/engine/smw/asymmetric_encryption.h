/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef __ASYMMETRIC_ENCRYPTION_H__
#define __ASYMMETRIC_ENCRYPTION_H__

#include "types.h"

/**
 * asymmetric_encrypt() - Perform asymmetric encryption operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * -SUBSYSTEM                   - Asymmetric eEncryption operation has failed.
 * -BAD_PARAM_TYPE              - A parameter value is undefined.
 * -MISSING_PARAMS              - Missing parameter in the test definition file.
 * -UNDEFINED_CMD               - Command is neither Sign nor Verify
 * Error code from key_desc_init().
 * Error code from key_read_descriptor().
 * Error code from util_read_hex_buffer().
 * Error code from util_asymm_enc_find_node().
 * Error code from set_asymm_encrypt_decrypt_bad_args().
 * Error code from util_asymm_enc_add_node().
 */
int asymmetric_encrypt(struct subtest_data *subtest);

/**
 * asymmetric_decrypt() - Perform asymmetric decryption operation.
 * @subtest: Subtest data.
 *
 * Return:
 * PASSED                       - Success.
 * -INTERNAL_OUT_OF_MEMORY      - Memory allocation failed.
 * -API_STATUS_NOK              - SMW API Call return error
 * -BAD_ARGS                    - One of the arguments is bad.
 * -SUBSYSTEM                   - Asymmetric decryption operation failed.
 * -BAD_PARAM_TYPE              - A parameter value is undefined.
 * -MISSING_PARAMS              - Missing parameter in the test definition file.
 * -UNDEFINED_CMD               - Command is neither Sign nor Verify
 * Error code from key_desc_init().
 * Error code from key_read_descriptor().
 * Error code from util_read_hex_buffer().
 * Error code from util_asymm_enc_find_node().
 * Error code from set_asymm_encrypt_decrypt_bad_args().
 * Error code from util_asymm_enc_add_node().
 */
int asymmetric_decrypt(struct subtest_data *subtest);

#endif /* __ASYMMETRIC_ENCRYPTION_H__ */
