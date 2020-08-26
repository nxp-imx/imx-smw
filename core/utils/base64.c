// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"
#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"
#include "base64.h"

#define PADDING_CHAR '=' /* Base64 padding character */
#define BAD_CHAR     0xFF

/* Hex to Base64 encoding table */
static const unsigned char encoding_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

/* Mask used to avoid encoding table buffer over-read */
#define ENC_MAX_ARRAY_MASK (ARRAY_SIZE(encoding_table) - 1)

unsigned int smw_utils_get_base64_len(unsigned int hex_len)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return ((hex_len + 2) / 3) * 4;
}

/**
 * get_hex_len - Calculate the hexadecimal length of a base64 buffer.
 * @base64: Base64 buffer.
 * @base64_len: @base64 length in bytes.
 *
 * Return:
 * 0	- @base64_len is invalid.
 * Hex buffer length in bytes.
 */
static unsigned int get_hex_len(const unsigned char *base64,
				unsigned int base64_len)
{
	unsigned int hex_len = 0;
	int i = base64_len;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(base64);

	if (base64_len % 4 || !base64_len)
		return 0;

	hex_len = (base64_len / 4) * 3;

	while (--i && base64[i] == PADDING_CHAR)
		hex_len--;

	return hex_len;
}

/**
 * convert_char() - Convert base64 char into hex char.
 * @c: Char to convert.
 *
 * Return:
 * Hex char.
 * BAD_CHAR if @c is invalid.
 */
static unsigned char convert_char(unsigned char c)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

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

int smw_utils_base64_encode(const unsigned char *in, unsigned int in_len,
			    unsigned char *base64, unsigned int *base64_len)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int len = 0;
	unsigned int rest = in_len;
	unsigned char *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(in && base64 && base64_len);

	len = smw_utils_get_base64_len(in_len);
	if (!len) {
		SMW_DBG_PRINTF(ERROR, "%s: Input buffer length is 0\n",
			       __func__);
		goto exit;
	}

	if (*base64_len < len) {
		SMW_DBG_PRINTF(ERROR, "%s: Base64 buffer too small (%d / %d)\n",
			       __func__, *base64_len, len);
		goto exit;
	}

	p = base64;

	while (rest >= 3) {
		/* Convert 3 input bytes into 4 Base64 bytes */
		*p++ = encoding_table[(*in >> 2) & ENC_MAX_ARRAY_MASK];
		*p++ = encoding_table[(((*in & 0x03) << 4) | (*(in + 1) >> 4)) &
				      ENC_MAX_ARRAY_MASK];
		*p++ = encoding_table[(((*(in + 1) & 0x0F) << 2) |
				       (*(in + 2) >> 6)) &
				      ENC_MAX_ARRAY_MASK];
		*p++ = encoding_table[(*(in + 2) & 0x3F) & ENC_MAX_ARRAY_MASK];

		rest -= 3;
		in += 3;
	}

	/* Convert last bytes and add padding */
	if (rest) {
		*p++ = encoding_table[(*in >> 2) & ENC_MAX_ARRAY_MASK];
		if (rest == 1) {
			*p++ = encoding_table[((*in & 0x03) << 4) &
					      ENC_MAX_ARRAY_MASK];
			*p++ = PADDING_CHAR;
		} else {
			*p++ = encoding_table[(((*in & 0x03) << 4) |
					       (*(in + 1) >> 4)) &
					      ENC_MAX_ARRAY_MASK];
			*p++ = encoding_table[((*(in + 1) & 0x0F) << 2) &
					      ENC_MAX_ARRAY_MASK];
		}
		*p++ = PADDING_CHAR;
	}

	*base64_len = len;
	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

int smw_utils_base64_decode(const unsigned char *base64,
			    unsigned int base64_len, unsigned char **hex,
			    unsigned int *hex_len)
{
	int status = SMW_STATUS_INVALID_PARAM;
	unsigned int i = 0;
	unsigned int len = 0;
	unsigned char *p = NULL;
	unsigned char *end = NULL;
	unsigned char decode[4] = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(base64 && hex_len);

	len = get_hex_len(base64, base64_len);
	if (!len) {
		SMW_DBG_PRINTF(ERROR, "%s: Base64 buffer length is invalid\n",
			       __func__);
		goto exit;
	}

	*hex = SMW_UTILS_MALLOC(len);
	if (!*hex) {
		SMW_DBG_PRINTF(ERROR, "%s: Alloc failed\n", __func__);
		status = SMW_STATUS_ALLOC_FAILURE;
		goto exit;
	}

	p = *hex;
	end = (unsigned char *)base64 + base64_len;

	while ((*base64 != PADDING_CHAR) && (base64 < end)) {
		/* Read 4 bytes to convert it in 3 */
		for (i = 0; (i < 4) && (*base64 != PADDING_CHAR); i++) {
			decode[i] = convert_char(*base64++);
			if (decode[i] == BAD_CHAR) {
				SMW_DBG_PRINTF(ERROR,
					       "%s: Base64 buffer is bad\n",
					       __func__);
				free(*hex);
				*hex = NULL;
				status = SMW_STATUS_INVALID_PARAM;
				goto exit;
			}
		}

		*p++ = (decode[0] << 2) | (decode[1] >> 4);
		if (i > 2) {
			*p++ = (decode[1] << 4) | (decode[2] >> 2);

			if (i > 3)
				*p++ = (decode[2] << 6) | decode[3];
			else
				break;
		} else {
			break;
		}
	}

	*hex_len = len;
	status = SMW_STATUS_OK;

exit:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
