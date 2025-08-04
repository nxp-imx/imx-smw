// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "trace.h"
#include "util.h"

#define PADDING_CHAR '=' /* Base64 padding character */
#define BAD_CHAR     0xFF

/* Hex to Base64 encoding table */
static const char encoding_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

/* Mask used to avoid encoding table buffer over-read */
#define ENC_MAX_ARRAY_MASK (ARRAY_SIZE(encoding_table) - 1)

static CK_BYTE divide_by_128(CK_BYTE_PTR bytes, size_t len)
{
	unsigned int remainder = 0;
	unsigned int current = 0;
	size_t i = 0;

	for (; i < len; i++) {
		current = (remainder << 8) | bytes[i];
		bytes[i] = (current >> 7) & UINT8_MAX;
		remainder = current % 128;
	}

	return remainder & UINT8_MAX;
}

static void multiply_add_128(CK_BYTE_PTR bytes, size_t len, CK_BYTE value)
{
	unsigned int carry = value;
	unsigned int tmp = 0;
	size_t i = len;

	for (; i > 0; i--) {
		tmp = bytes[i - 1] << 7;

		if (ADD_OVERFLOW(tmp, carry, &tmp))
			tmp = 0;

		bytes[i - 1] = tmp & 0xFF;
		carry = tmp >> 8;
	}
}

static int is_zero(CK_BYTE_PTR bytes, size_t len)
{
	size_t i = 0;

	for (; i < len; i++) {
		if (bytes[i] != 0)
			return 0;
	}

	return 1;
}

static size_t get_b64_from_hex_len(size_t hex_len)
{
	size_t b64_len = 0;

	b64_len = hex_len + 2;
	b64_len /= 3;
	if (MUL_OVERFLOW(b64_len, 4, &b64_len))
		b64_len = 0;

	return b64_len;
}

static size_t get_hex_from_b64_len(const char *base64, size_t base64_len)
{
	size_t hex_len = 0;
	size_t i = base64_len;

	if (base64_len % 4 || !base64_len)
		return 0;

	hex_len = (base64_len / 4) * 3;

	while (--i && base64[i] == PADDING_CHAR && hex_len)
		hex_len--;

	return hex_len;
}

static unsigned char conv_b64_to_hex(unsigned char c)
{
	if (c >= 'A' && c <= 'Z')
		return (c - 'A');
	else if (c >= 'a' && c <= 'z')
		return (c - 'a' + 26);
	else if (c >= '0' && c <= '9')
		return (c - '0' + 52);
	else if (c == '+')
		return 62;
	else if (c == '/')
		return 63;

	return BAD_CHAR;
}

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

size_t util_byte_to_rfc2279_len(const CK_BYTE_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src; idx++, len++)
		if (src[idx] > 0x7F) {
			if (INC_OVERFLOW(len, 1))
				return 0;
		}

	return len;
}

size_t util_byte_to_rfc2279(CK_UTF8CHAR_PTR dst, size_t len_dst,
			    const CK_BYTE_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src && len < len_dst; idx++, len++) {
		if (src[idx] > 0x7F) {
			if (len_dst <= len + 1)
				return idx;

			dst[len] = ((src[idx] >> 6) & 0x1F) | 0xC0;
			dst[++len] = (src[idx] & 0x3F) | 0x80;
		} else {
			dst[len] = src[idx];
		}
	}

	return idx;
}

size_t util_rfc2279_to_byte_len(const CK_UTF8CHAR_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src; idx++) {
		if ((src[idx] & 0xE0) == 0xE0) {
			return 0;
		} else if ((src[idx] & 0xC0) == 0x80) {
			return 0;
		} else if ((src[idx] & 0xE0) == 0xC0) {
			if (len_src <= idx + 1)
				return 0;

			if ((src[++idx] & 0xC0) != 0x80)
				return 0;

			if (INC_OVERFLOW(len, 1))
				return 0;
		} else {
			if (INC_OVERFLOW(len, 1))
				return 0;
		}
	}

	return len;
}

size_t util_rfc2279_to_byte(CK_BYTE_PTR dst, size_t len_dst,
			    const CK_UTF8CHAR_PTR src, size_t len_src)
{
	size_t len = 0;
	size_t idx = 0;

	for (; idx < len_src && len < len_dst; idx++, len++) {
		if ((src[idx] & 0xE0) == 0xE0) {
			return idx;
		} else if ((src[idx] & 0xC0) == 0x80) {
			return idx;
		} else if ((src[idx] & 0xE0) == 0xC0) {
			if (len_src <= idx + 1)
				return idx;

			if ((src[idx + 1] & 0xC0) != 0x80)
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

CK_RV util_base64_encode(char **base64, struct libbytes *src)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	size_t len_b64 = 0;
	size_t rest = 0;
	CK_BYTE_PTR in = NULL;
	char *tmp_b64 = NULL;
	char *p = NULL;
	size_t index = 0;

	if (!base64 || !src || !src->array || !src->number)
		goto exit;

	rest = src->number;
	in = src->array;

	len_b64 = get_b64_from_hex_len(src->number);
	if (!len_b64) {
		DBG_TRACE("Error Input buffer length is 0");
		goto exit;
	}

	tmp_b64 = calloc(1, len_b64 + 1 /* Null terminated string */);
	if (!tmp_b64) {
		DBG_TRACE("Allocation error of the Base64 buffer");
		ret = CKR_HOST_MEMORY;
		goto exit;
	}

	p = tmp_b64;

	while (rest >= 3) {
		/* Convert 3 input bytes into 4 Base64 bytes */
		index = (*in >> 2) & ENC_MAX_ARRAY_MASK;
		*p++ = encoding_table[index];

		index = (*in & 0x03) << 4;
		index |= *(in + 1) >> 4;
		index &= ENC_MAX_ARRAY_MASK;
		*p++ = encoding_table[index];

		index = (*(in + 1) & 0x0F) << 2;
		index |= (*(in + 2) >> 6);
		index &= ENC_MAX_ARRAY_MASK;
		*p++ = encoding_table[index];

		index = (*(in + 2) & 0x3F) & ENC_MAX_ARRAY_MASK;
		*p++ = encoding_table[index];

		rest -= 3;
		in += 3;
	}

	/* Convert last bytes and add padding */
	if (rest) {
		*p++ = encoding_table[(*in >> 2) & ENC_MAX_ARRAY_MASK];
		if (rest == 1) {
			index = ((*in & 0x03) << 4) & ENC_MAX_ARRAY_MASK;
			*p++ = encoding_table[index];

			*p++ = PADDING_CHAR;
		} else {
			index = (*in & 0x03) << 4;
			index |= *(in + 1) >> 4;
			index &= ENC_MAX_ARRAY_MASK;
			*p++ = encoding_table[index];

			index = ((*(in + 1) & 0x0F) << 2) & ENC_MAX_ARRAY_MASK;
			*p++ = encoding_table[index];
		}
		*p++ = PADDING_CHAR;
	}

	*base64 = tmp_b64;
	ret = CKR_OK;

exit:
	return ret;
}

CK_RV util_base64_decode(struct libbytes *out, const char *base64)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	size_t i = 0;
	size_t len = 0;
	CK_BYTE_PTR tmp_hex = NULL;
	CK_BYTE_PTR p = NULL;
	const char *end_b64 = NULL;
	CK_BYTE decode[4] = { 0 };

	if (!out || !base64)
		goto exit;

	len = get_hex_from_b64_len(base64, strlen(base64));
	if (!len) {
		DBG_TRACE("Error Base64 buffer length is invalid");
		goto exit;
	}

	tmp_hex = malloc(len);
	if (!tmp_hex) {
		DBG_TRACE("Allocation error of the hexadecimal buffer");
		ret = CKR_HOST_MEMORY;
		goto exit;
	}

	p = tmp_hex;
	end_b64 = base64 + strlen(base64);

	while ((*base64 != PADDING_CHAR) && (base64 < end_b64)) {
		/* Read 4 bytes to convert it in 3 */
		for (i = 0; (i < 4) && (*base64 != PADDING_CHAR); i++) {
			decode[i] = conv_b64_to_hex(*base64++);
			if (decode[i] == BAD_CHAR) {
				DBG_TRACE("Base64 buffer is bad");
				ret = CKR_FUNCTION_FAILED;
				goto exit;
			}
		}

		*p = (decode[0] << 2) & UCHAR_MAX;
		*p |= decode[1] >> 4;
		p++;

		if (i <= 2)
			break;

		*p = (decode[1] << 4) & UCHAR_MAX;
		*p |= decode[2] >> 2;
		p++;

		if (i <= 3)
			break;

		*p = (decode[2] << 6) & UCHAR_MAX;
		*p |= decode[3];
		p++;
	}

	out->array = tmp_hex;
	out->number = len;
	ret = CKR_OK;

exit:
	if (ret != CKR_OK && tmp_hex)
		free(tmp_hex);

	return ret;
}

CK_RV util_base128_encode(struct libbytes *out, struct libbytes *in)
{
	CK_RV ret = CKR_DATA_INVALID;
	CK_BYTE *work = NULL;
	CK_BYTE tmp = 0;
	size_t i = 0;

	if (!in->number)
		goto end;

	work = malloc(in->number);
	if (!work) {
		DBG_TRACE("Allocation error");
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	/* First pass, calculate the out->number */
	memcpy(work, in->array, in->number);

	out->number = 0;
	while (!is_zero(work, in->number)) {
		(void)divide_by_128(work, in->number);
		if (INC_OVERFLOW(out->number, 1)) {
			ret = CKR_DATA_INVALID;
			goto end;
		}
	}

	if (!out->number) {
		ret = CKR_DATA_INVALID;
		goto end;
	}

	/* Allocate the out->array buffer */
	out->array = malloc(out->number);
	if (!out->array) {
		DBG_TRACE("Allocation error");
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	/* Second pass, fill the out->array */
	memcpy(work, in->array, in->number);

	while (!is_zero(work, in->number))
		out->array[i++] = divide_by_128(work, in->number);

	/* Reverse in-place and apply continuation bits after */
	for (i = 0; i < out->number / 2; i++) {
		tmp = out->array[i];
		out->array[i] = out->array[out->number - i - 1];
		out->array[out->number - i - 1] = tmp;
	}

	for (i = 0; i < out->number - 1; i++)
		out->array[i] |= 0x80;

	ret = CKR_OK;

end:
	if (work)
		free(work);

	return ret;
}

CK_RV util_base128_decode(struct libbytes *out, struct libbytes *in)
{
	CK_BYTE byte = 0;
	size_t i = 0;

	if (!in->number)
		return CKR_DATA_INVALID;

	out->number = in->number;

	/* Allocate the out->array buffer */
	out->array = calloc(out->number, 1);
	if (!out->array) {
		DBG_TRACE("Allocation error");
		return CKR_HOST_MEMORY;
	}

	for (; i < in->number; i++) {
		byte = in->array[i] & 0x7F;
		multiply_add_128(out->array, out->number, byte);
	}

	return CKR_OK;
}
