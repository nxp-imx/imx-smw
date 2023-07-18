/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020, 2023 NXP
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>

#include "builtin_macros.h"

#include "pkcs11smw.h"
#include "types.h"

#define TO_CK_BYTES(out, val)                                                  \
	({                                                                     \
		__typeof__(out) _out = (out);                                  \
		for (size_t i = 0; i < sizeof(val); i++)                       \
			_out[i] = GET_BYTE(val, i);                            \
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

/**
 * util_get_bignum_bits() - Get the number of bits of a big number
 * @bignum: Big number
 *
 * Return:
 * The number of bits of the big number
 */
size_t util_get_bignum_bits(struct libbignumber *bignum);

#endif /* __UTIL_H__ */
