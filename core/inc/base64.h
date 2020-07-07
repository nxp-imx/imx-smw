/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

/**
 * smw_utils_base64_encode() - Encode hex buffer into base64 buffer.
 * @in: Input hex buffer.
 * @in_len: @in length in bytes.
 * @base64: Output base64 buffer. It's allocated by the function and must be
 *          freed by caller.
 * @base64_len: @base64 length in bytes. Not updated if function returned an
 *              error.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failed.
 * SMW_STATUS_OPERATION_FAILURE	- Operation failed.
 */
int smw_utils_base64_encode(const unsigned char *in, unsigned int in_len,
			    unsigned char **base64, unsigned int *base64_len);

/**
 * smw_utils_base64_decode() - Decode base64 buffer into hex buffer.
 * @base64: Base64 buffer.
 * @base64_len: @base64 length in bytes.
 * @hex: Output hex buffer. It's allocated by the function and must be freed by
 *       caller.
 * @hex_len: @hex length in bytes. Not updated if function returned an error.
 *
 * Return:
 * SMW_STATUS_OK		- Success.
 * SMW_STATUS_INVALID_PARAM	- One of the parameter is invalid.
 * SMW_STATUS_ALLOC_FAILURE	- Memory allocation failed.
 * SMW_STATUS_OPERATION_FAILURE	- Operation failed.
 */
int smw_utils_base64_decode(const unsigned char *base64,
			    unsigned int base64_len, unsigned char **hex,
			    unsigned int *hex_len);
