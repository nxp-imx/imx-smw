/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2024 NXP
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include <pkcs11smw.h>

#include "config.h"

bool util_compare_buffers(unsigned char *buffer, size_t buffer_len,
			  unsigned char *expected_buffer, size_t expected_len);

bool is_seco_subsystem(void);
bool is_ele_subsystem(void);
bool is_8ulp(void);
CK_RV util_set_unique_id(CK_UTF8CHAR_PTR unique_id, CK_ULONG_PTR length,
			 CK_OBJECT_CLASS class, unsigned int id);
CK_RV util_get_object_id(CK_UTF8CHAR_PTR unique_id, CK_ULONG length,
			 unsigned int *object_id);

#endif /* __UTIL_H__ */
