/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2026 NXP
 */

#ifndef __ENDIAN_H__
#define __ENDIAN_H__

#include <stdint.h>
/**
 * smw_utils_convert_endian() - Convert endianness of a buffer
 * @src: Pointer to the source buffer
 * @dst: Pointer to the destination buffer (can be NULL for in-place conversion)
 * @size: Size of the buffer in bytes
 *
 * This function converts the endianness of a buffer. If @dst is NULL,
 * the conversion is done in-place on @src.
 *
 * Return:
 * SMW_STATUS_OK                       - Success
 * SMW_STATUS_INVALID_PARAM            - One of the parameter is invalid.
 */
int smw_utils_convert_endian(unsigned char *src, unsigned char *dst,
			     unsigned int size);

#endif /* __ENDIAN_H__ */
