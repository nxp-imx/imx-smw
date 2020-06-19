/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include "pkcs11smw.h"

/*
 * Useful macros
 */
#define BIT(bit)	      (1 << (bit))
#define SET_BITS(val, mask)   ((val) |= (mask))
#define CLEAR_BITS(val, mask) ((val) &= ~(mask))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif /* ARRAY_SIZE */

#ifndef MIN
#define MIN(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _a : _b;                                             \
	})
#endif /* MIN */

#define STR(x) #x

#define ADD_OVERFLOW(a, b, res) __builtin_add_overflow(a, b, res)

/**
 * util_check_ptrs_null() - Verify all given pointers are NULL
 * @nb: Number of pointers to verify
 * @...: Dynamic parameters list
 *
 * Return: True if all pointers are NULL, otherwise false
 */
bool util_check_ptrs_null(int nb, ...);

/**
 * util_check_ptrs_set() - Verify all given pointers are not NULL
 * @nb: Number of pointers to verify
 * @...: Dynamic parameters list
 *
 * Return: True if all pointers are not NULL, otherwise false
 */
bool util_check_ptrs_set(int nb, ...);

/**
 * util_copy_str_to_utf8() - Copy a string char to utf8
 * @dst: Destination string
 * @len_dst: Length of the destination string
 * @src: Source string
 *
 * Copy a null terminated string to a UTF8 string and complete the
 * UTF8 string with spaces.
 */
void util_copy_str_to_utf8(CK_UTF8CHAR_PTR dst, size_t len_dst,
			   const char *src);

#endif /* __UTIL_H__ */
