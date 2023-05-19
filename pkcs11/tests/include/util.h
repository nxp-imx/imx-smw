/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include <stddef.h>
#include <stdbool.h>

bool util_compare_buffers(unsigned char *buffer, size_t buffer_len,
			  unsigned char *expected_buffer, size_t expected_len);

#endif /* __UTIL_H__ */
