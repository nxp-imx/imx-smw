/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020, 2023-2025 NXP
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

#define TO_INT(out, buf, len)                                                  \
	({                                                                     \
		__typeof__(out) _out = 0;                                      \
		__typeof__(buf) _buf = (buf);                                  \
		size_t i = len;                                                \
		int ret = 0;                                                   \
		if (i > sizeof(_out)) {                                        \
			ret = 1;                                               \
		} else {                                                       \
			_out = _buf[--i] & UINT8_MAX;                          \
			for (; i; i--) {                                       \
				_out <<= 8;                                    \
				_out |= _buf[i - 1] & UINT8_MAX;               \
			}                                                      \
			out = _out;                                            \
		}                                                              \
		ret;                                                           \
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
 * util_byte_to_rfc2279_len() - Get the RFC2279 string length of a byte array
 * @src: Byte array
 * @len_src: Length of the @src array
 *
 * Return:
 * RFC2279 length of the byte array
 */
size_t util_byte_to_rfc2279_len(const CK_BYTE_PTR src, size_t len_src);

/**
 * util_byte_to_rfc2279() - Convert a byte array to an RFC2279 string
 * @dst: RFC2279 string output
 * @len_dst: RFC2279 string length maximum
 * @src: Byte array to convert
 * @len_src: Length of the @src array
 *
 * Return:
 * The number of source byte converted
 */
size_t util_byte_to_rfc2279(CK_UTF8CHAR_PTR dst, size_t len_dst,
			    const CK_BYTE_PTR src, size_t len_src);

/**
 * util_rfc2279_to_byte_len() - Get the byte array length of an RFC2279 string
 * @src: RFC2279 string
 * @len_src: Length of the @src string
 *
 * Return:
 * byte array length of the RFC2279 string
 */
size_t util_rfc2279_to_byte_len(const CK_UTF8CHAR_PTR src, size_t len_src);

/**
 * util_rfc2279_to_byte() - Convert an RFC2279 string to an array of byte
 * @dst: Byte array to convert
 * @len_dst: Length of the @src array
 * @src: RFC2279 string output
 * @len_src: RFC2279 string length maximum
 *
 * Return:
 * The length of RFC2279 string converted
 */
size_t util_rfc2279_to_byte(CK_BYTE_PTR dst, size_t len_dst,
			    const CK_UTF8CHAR_PTR src, size_t len_src);

/**
 * util_get_bignum_bits() - Get the number of bits of a big number
 * @bignum: Big number
 *
 * Return:
 * The number of bits of the big number
 */
size_t util_get_bignum_bits(struct libbignumber *bignum);

/**
 * util_base64_encode() - Encode a byte array to a base64 null terminated string
 * @base64: [out] Base64 null terminated string
 * @out: [in] Byte array
 *
 * Return:
 * CKR_OK               - Success
 * CKR_FUNCTION_FAILED  - Failure
 * CKR_HOST_MEMORY      - Out of memory
 */
CK_RV util_base64_encode(char **base64, struct libbytes *src);

/**
 * util_base64_decode() - Decode a base64 null terminated string to byte array
 * @out: [out] Byte array
 * @base64: [in] Base64 null terminated string
 *
 * Return:
 * CKR_OK               - Success
 * CKR_FUNCTION_FAILED  - Failure
 * CKR_HOST_MEMORY      - Out of memory
 */
CK_RV util_base64_decode(struct libbytes *out, const char *base64);

#endif /* __UTIL_H__ */
