// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "builtin_macros.h"

#include "util.h"
#include "test_check.h"

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

static size_t byte_to_rfc2279_len(const CK_BYTE_PTR src, size_t len_src)
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

static size_t byte_to_rfc2279(CK_UTF8CHAR_PTR dst, size_t len_dst,
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

static size_t rfc2279_to_byte_len(const CK_UTF8CHAR_PTR src, size_t len_src)
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

static size_t rfc2279_to_byte(CK_BYTE_PTR dst, size_t len_dst,
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

static CK_RV decode_asn1_length(const uint8_t *in, size_t *inlen,
				size_t *outlen)
{
	size_t real_len = 0;
	size_t decoded_len = 0;
	size_t offset = 0;
	size_t x = 0;
	size_t i = 0;

	if (*inlen < 1)
		return CKR_ARGUMENTS_BAD;

	real_len = in[0];

	if (real_len < 128) {
		decoded_len = real_len;
		offset = 1;
	} else {
		real_len &= 0x7F;

		if (real_len == 0)
			return CKR_DATA_INVALID;

		if (real_len > sizeof(decoded_len))
			return CKR_DATA_INVALID;

		if (real_len > (*inlen - 1))
			return CKR_DATA_INVALID;

		decoded_len = 0;
		offset = 1 + real_len;

		for (; i < real_len; i++)
			decoded_len = (decoded_len << 8) | in[1 + i];
	}

	if (outlen)
		*outlen = decoded_len;

	if (SUB_OVERFLOW(*inlen, offset, &x))
		return CKR_ARGUMENTS_BAD;

	if (decoded_len > x)
		return CKR_DATA_INVALID;

	*inlen = offset;

	return CKR_OK;
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

CK_RV util_set_unique_id(CK_UTF8CHAR_PTR unique_id, CK_ULONG_PTR length,
			 CK_OBJECT_CLASS class, unsigned int id)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	CK_BYTE_PTR buffer = NULL_PTR;
	CK_ULONG size = 0;
	CK_ULONG unique_id_length = 0;

	if (!length)
		return ret;

	size = sizeof(CK_OBJECT_CLASS) + sizeof(id);
	buffer = malloc(size);
	if (!buffer)
		return CKR_HOST_MEMORY;

	TO_CK_BYTES(&buffer[sizeof(CK_OBJECT_CLASS)], id);
	TO_CK_BYTES(buffer, class);

	/* Get RFC2279 length and allocate RFC2279 string */
	unique_id_length = byte_to_rfc2279_len(buffer, size);
	if (!unique_id_length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (!unique_id || *length < unique_id_length) {
		ret = CKR_BUFFER_TOO_SMALL;
		*length = unique_id_length;
		goto end;
	}

	ret = CKR_FUNCTION_FAILED;
	if (byte_to_rfc2279(unique_id, unique_id_length, buffer, size) == size)
		ret = CKR_OK;

end:
	if (buffer)
		free(buffer);

	return ret;
}

CK_RV util_get_object_id(CK_UTF8CHAR_PTR unique_id, CK_ULONG length,
			 unsigned int *object_id)
{
	int ret = CKR_OK;

	CK_BYTE_PTR buffer = NULL_PTR;
	CK_ULONG size = 0;

	if (!length)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	size = rfc2279_to_byte_len(unique_id, length);
	if (!size)
		return CKR_FUNCTION_FAILED;

	buffer = malloc(size);
	if (!buffer)
		return CKR_HOST_MEMORY;

	if (rfc2279_to_byte(buffer, size, unique_id, length) != length) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	if (TO_INT(*object_id, &buffer[sizeof(CK_OBJECT_CLASS)],
		   sizeof(unsigned int)))
		ret = CKR_ATTRIBUTE_VALUE_INVALID;

end:
	if (buffer)
		free(buffer);

	return ret;
}

CK_RV util_decode_octet_string(uint8_t *in, size_t inlen, uint8_t **out,
			       size_t *outlen)
{
	CK_RV ret = CKR_OK;
	size_t x = 0;
	size_t y = 0;
	size_t len = 0;

	/* must have header at least */
	if (inlen < 2)
		return CKR_ARGUMENTS_BAD;

	/* check for 0x04 */
	if ((in[0] & 0x1F) != 0x04)
		return CKR_DATA_INVALID;

	x = 1;

	/* get the length of the data */
	y = inlen - x;

	ret = decode_asn1_length(in + x, &y, &len);
	if (ret != CKR_OK)
		return ret;

	if (ADD_OVERFLOW(x, y, &x))
		return CKR_ARGUMENTS_BAD;

	if (SUB_OVERFLOW(inlen, x, &inlen))
		return CKR_ARGUMENTS_BAD;

	if (len > inlen)
		return CKR_DATA_INVALID;

	*out = in + x;
	*outlen = len;

	return CKR_OK;
}
