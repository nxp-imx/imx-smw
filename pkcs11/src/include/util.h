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

#ifndef MAX
#define MAX(a, b)                                                              \
	({                                                                     \
		__typeof__(a) _a = (a);                                        \
		__typeof__(b) _b = (b);                                        \
		_a < _b ? _b : _a;                                             \
	})
#endif /* MAX */

#define STR(x) #x

#define ADD_OVERFLOW(a, b, res) __builtin_add_overflow(a, b, res)

#define TO_CK_BYTES(out, val)                                                  \
	({                                                                     \
		__typeof__(out) _out = (out);                                  \
		__typeof__(val) _val = (val);                                  \
		for (size_t i = 0; i < sizeof(val); i++, _val >>= 8)           \
			_out[i] = (CK_BYTE)_val;                               \
	})

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

/**
 * util_byte_to_utf8_len() - Get the UTF8 string length of a byte array
 * @src: Byte array
 * @len_src: Length of the @src array
 *
 * Return:
 * UTF8 length of the byte array
 */
size_t util_byte_to_utf8_len(const CK_BYTE_PTR src, size_t len_src);

/**
 * util_byte_to_utf8() - Convert a byte array to an UTF8 string
 * @dst: UTF8 string output
 * @len_dst: UTF8 string length maximum
 * @src: Byte array to convert
 * @len_src: Length of the @src array
 *
 * Return:
 * The number of source byte converted
 */
size_t util_byte_to_utf8(CK_UTF8CHAR_PTR dst, size_t len_dst,
			 const CK_BYTE_PTR src, size_t len_src);

/**
 * util_utf8_to_byte_len() - Get the byte array length of an UTF8 string
 * @src: UTF8 string
 * @len_src: Length of the @src string
 *
 * Return:
 * byte array length of the UTF8 string
 */
size_t util_utf8_to_byte_len(const CK_UTF8CHAR_PTR src, size_t len_src);

/**
 * util_utf8_to_byte() - Convert an UTF8 string to an array of byte
 * @dst: Byte array to convert
 * @len_dst: Length of the @src array
 * @src: UTF8 string output
 * @len_src: UTF8 string length maximum
 *
 * Return:
 * The length of UTF8 string converted
 */
size_t util_utf8_to_byte(CK_BYTE_PTR dst, size_t len_dst,
			 const CK_UTF8CHAR_PTR src, size_t len_src);

#endif /* __UTIL_H__ */
