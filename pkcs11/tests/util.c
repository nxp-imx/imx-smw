// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "util.h"
#include <string.h>

bool util_compare_buffers(unsigned char *buffer, size_t buffer_len,
			  unsigned char *expected_buffer, size_t expected_len)
{
	bool status = false;

	if (buffer_len != expected_len)
		return status;

	if (buffer && expected_buffer &&
	    !memcmp(buffer, expected_buffer, buffer_len)) {
		status = true;
	}

	return status;
}
