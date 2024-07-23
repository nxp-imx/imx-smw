// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "test_check.h"

/**
 * string_to_lower() - Convert a string to lowercase
 * @src: String to convert
 * @length: Length of source string to convert
 */
static void string_to_lower(char *src, size_t length)
{
	for (size_t idx = 0; idx < strlen(src) && idx < length; idx++) {
		if (src[idx] >= 'A' && src[idx] <= 'Z')
			src[idx] += 'a' - 'A';
	}
}

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

bool is_seco_subsystem(void)
{
#if SECO_TESTS_ENABLED
	return true;
#else
	return false;
#endif
}

bool is_ele_subsystem(void)
{
#if ELE_TESTS_ENABLED
	return true;
#else
	return false;
#endif
}

bool is_8ulp(void)
{
	char hostname[256] = { 0 };
	const char *device = "imx8ulp";

	if (gethostname(hostname, sizeof(hostname))) {
		TEST_OUT("%s (%d): Unable to get the hostname\n", __func__,
			 __LINE__);
		return false;
	}

	string_to_lower(hostname, strlen(hostname));

	if (!strncmp(hostname, device, strlen(device)))
		return true;

	return false;
}
