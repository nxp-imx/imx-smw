/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __MATH_H__
#define __MATH_H__

#include "debug.h"
#include "smw_status.h"
#include "builtin_macros.h"

/**
 * smw_utils_align_value() - Align value up to the next multiple of alignment
 * @value: Value to align
 * @alignment: Alignment boundary (must be power of 2)
 * @result: Pointer to store aligned result
 *
 * Aligns @value up to the next multiple of @alignment. @result is updated
 * only if the alignment operation is successful.
 *
 * ELA hardware requires 64-byte alignment for i/p and o/p buffers.
 *
 * Example:
 *   align_value(100, 64, &result) -> result = 128
 *   align_value(128, 64, &result) -> result = 128
 *   align_value(4, 64, &result)   -> result = 64
 *
 * Return:
 * SMW_STATUS_OK             - @result contains the aligned value
 * SMW_STATUS_INVALID_PARAM  - Invalid parameters or overflow
 */
int smw_utils_align_value(unsigned int value, unsigned int alignment,
			  unsigned int *result);

#endif /* __MATH_H__ */
