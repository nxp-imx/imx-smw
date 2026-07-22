// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "smw_status.h"

int smw_utils_convert_endian(unsigned char *src, unsigned char *dst,
			     unsigned int size)
{
	unsigned int i = 0;

	if (!src || size == 0)
		return SMW_STATUS_INVALID_PARAM;

	if (dst) {
		for (; i < size; i++)
			dst[i] = src[size - 1 - i];
	} else {
		for (; i < size / 2; i++) {
			src[i] ^= src[size - 1 - i];
			src[size - 1 - i] ^= src[i];
			src[i] ^= src[size - 1 - i];
		}
	}

	return SMW_STATUS_OK;
}
