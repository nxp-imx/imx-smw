// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021,2023 NXP
 */
#include <stdarg.h>
#include <string.h>

#include "trace.h"
#include "util.h"

bool util_check_ptrs_null(int nb, ...)
{
	void *ptr = NULL;
	va_list args = { 0 };
	int idx = 0;
	int nb_null = 0;

	va_start(args, nb);

	for (idx = 0; idx < nb; idx++) {
		ptr = va_arg(args, void *);
		if (!ptr) {
			if (INC_OVERFLOW(nb_null, 1))
				break;
		}

		DBG_TRACE("Parameter %d=%p", idx, ptr);
	}
	va_end(args);

	return (nb_null == nb);
}

bool util_check_ptrs_set(int nb, ...)
{
	void *ptr = NULL;
	va_list args = { 0 };
	int idx = 0;
	int nb_set = 0;

	va_start(args, nb);

	for (idx = 0; idx < nb; idx++) {
		ptr = va_arg(args, void *);
		if (ptr) {
			if (INC_OVERFLOW(nb_set, 1))
				break;
		}

		DBG_TRACE("Parameter %d=%p", idx, ptr);
	}

	va_end(args);

	return (nb_set == nb);
}

void util_copy_str_to_utf8(CK_UTF8CHAR_PTR dst, size_t len_dst, const char *src)
{
	size_t len_src = 0;

	len_src = strlen(src);

	DBG_TRACE("SRC %zu vs %zu - %s", len_src, len_dst, src);
	memcpy(dst, src, MIN(len_dst, len_src));

	if (len_src < len_dst)
		memset(dst + len_src, ' ', len_dst - len_src);
}

size_t util_byte_to_utf8_len(const CK_BYTE_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src; idx++, len++)
		if (src[idx] > 0x7F) {
			if (INC_OVERFLOW(len, 1))
				return 0;
		}

	return len + 1;
}

size_t util_byte_to_utf8(CK_UTF8CHAR_PTR dst, size_t len_dst,
			 const CK_BYTE_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src && len < len_dst; idx++, len++) {
		if (src[idx] > 0x7F) {
			if (len_dst <= len + 2)
				return idx;

			dst[len] = ((src[idx] >> 6) & 0x1F) | 0xC0;
			dst[++len] = (src[idx] & 0x3F) | 0x80;
		} else {
			dst[len] = src[idx];
		}
	}

	return idx;
}

size_t util_utf8_to_byte_len(const CK_UTF8CHAR_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src; idx++)
		if ((src[idx] & 0xC0) != 0x80) {
			if (INC_OVERFLOW(len, 1))
				return 0;
		}

	return len + 1;
}

size_t util_utf8_to_byte(CK_BYTE_PTR dst, size_t len_dst,
			 const CK_UTF8CHAR_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src && len < len_dst; idx++, len++) {
		if (src[idx] & 0xC0) {
			if (len_src <= idx + 2)
				return idx;

			dst[len] = src[idx] << 6;
			dst[len] |= src[++idx] & 0x3F;
		} else {
			dst[len] = src[idx];
		}
	}

	return idx;
}

size_t util_get_bignum_bits(struct libbignumber *bignum)
{
	size_t nb_bits = 0;
	int msb = 0;
	size_t i = 0;

	if (MUL_OVERFLOW(bignum->length, 8, &nb_bits))
		return 0;

	for (i = 0; i < bignum->length; i++) {
		msb = bignum->value[i];
		if (msb) {
			while (!(msb & 0x80)) {
				if (DEC_OVERFLOW(nb_bits, 1))
					return 0;

				msb <<= 1;
			}
			break;
		}

		nb_bits -= 8;
	}

	return nb_bits;
}
