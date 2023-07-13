// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdint.h>
#include <stddef.h>

#include "debug.h"
#include "utils.h"

#include "asn1.h"

#define ASN1_LONG_LENGTH  BIT(7)
#define ASN1_TAG_SEQUENCE 0x30 /* (16 | 0x20) */
#define ASN1_TAG_INTEGER  2

static size_t get_length_field_length(size_t length)
{
	size_t len = 1;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (length > 0x7F)
		while (length) {
			if (INC_OVERFLOW(len, 1)) {
				len = 0;
				break;
			}

			length >>= 8;
		}

	return len;
}

static size_t get_sequence_length(struct asn1_integer sequence[], size_t size)
{
	size_t len = 0;
	size_t length = 0;
	size_t nb_length_bytes = 0;
	uint8_t *value = NULL;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!sequence || !size)
		return 0;

	for (; i < size; i++) {
		length = sequence[i].length;
		value = sequence[i].value;
		if (length) {
			if (!value)
				return 0;
			if (*value & ASN1_LONG_LENGTH)
				length++;
		}

		/* Tag */
		if (INC_OVERFLOW(len, 1))
			return 0;

		/* Length */
		nb_length_bytes = get_length_field_length(length);
		if (!nb_length_bytes)
			return 0;

		if (ADD_OVERFLOW(len, nb_length_bytes, &len))
			return 0;

		/* Value */
		if (ADD_OVERFLOW(len, length, &len))
			return 0;
	}

	return len;
}

static int encode_length(uint8_t **data, const uint8_t *end, size_t length)
{
	size_t len = 0;
	uint8_t *p = NULL;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !*data || !end)
		return -1;

	len = get_length_field_length(length);
	if (!len || len > sizeof(length))
		return -1;

	if (*data + len > end)
		return -1;

	i = len - 1;
	p = *data;

	if (!i)
		*p++ = length & UINT8_MAX;
	else
		*p++ = ASN1_LONG_LENGTH | i;

	while (i--)
		*p++ = (length >> (8 * i)) & UINT8_MAX;

	SMW_DBG_ASSERT(*data + len == p);
	if (*data + len != p)
		return -1;

	SMW_DBG_PRINTF(DEBUG, "Encode ASN.1 length field (%zu)\n", length);
	SMW_DBG_HEX_DUMP(DEBUG, *data, len, 4);

	*data = p;

	return 0;
}

static int encode_integer(uint8_t **data, const uint8_t *end, uint8_t *integer,
			  size_t length)
{
	uint8_t *p = NULL;
	size_t len = length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !*data || !end || !integer || !length)
		return -1;

	p = *data;

	/* Tag INTEGER */
	*p++ = ASN1_TAG_INTEGER;
	if (p > end)
		return -1;

	/* Length */
	if (integer[0] & ASN1_LONG_LENGTH)
		if (INC_OVERFLOW(len, 1))
			return -1;

	if (encode_length(&p, end, len))
		return -1;

	if (p + length > end)
		return -1;

	/* Value */
	if (integer[0] & 0x80)
		*p++ = 0;

	SMW_UTILS_MEMCPY(p, integer, length);
	p += length;

	*data = p;

	return 0;
}

size_t asn1_encode_sequence_integer(uint8_t *data, size_t data_size,
				    struct asn1_integer sequence[], size_t size)
{
	uint8_t *p = NULL;
	uint8_t *end = NULL;
	size_t sequence_length = 0;
	size_t i = 0;
	size_t enc_bytes = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_size || !sequence || !size)
		return 0;

	p = data;
	end = data + data_size;

	/* Tag SEQUENCE */
	*p++ = ASN1_TAG_SEQUENCE;
	if (p > end)
		return 0;

	/* Length */
	sequence_length = get_sequence_length(sequence, size);
	if (!sequence_length)
		return 0;

	if (encode_length(&p, end, sequence_length))
		return 0;

	/* Value */
	for (i = 0; i < size; i++) {
		if (encode_integer(&p, end, sequence[i].value,
				   sequence[i].length))
			return 0;
	}

	if (SUB_OVERFLOW((uintptr_t)p, (uintptr_t)data, &enc_bytes))
		enc_bytes = 0;

	return enc_bytes;
}

static void decode_length(const uint8_t **data, const uint8_t *end,
			  size_t *length)
{
	size_t len = 0;
	int i = 0;
	const uint8_t *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !*data || !end || !length)
		return;

	if (*data >= end)
		return;

	p = *data;

	if (*p & ASN1_LONG_LENGTH) {
		len = *p++ & 0x7F;
		if (len > sizeof(*length) || len > (unsigned int)(end - p)) {
			*data = end;
			return;
		}

		if (!len) {
			*length = 0;
		} else {
			*length = *p++;

			i = len - 1;
			while (i-- > 0) {
				*length <<= 8;
				*length += *p++;
			}
		}
	} else {
		*length = *p++;
	}

	SMW_DBG_PRINTF(DEBUG, "Decode ASN.1 length field (%zu)\n", *length);
	SMW_DBG_HEX_DUMP(DEBUG, *data, len + 1, 4);

	*data = p;
}

static void remove_leading_zeros(const uint8_t **data, const uint8_t *end,
				 size_t *length)
{
	const uint8_t *p = NULL;
	size_t len = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !*data || !end || !length)
		return;

	p = *data;
	len = *length;

	while (!*p && p < end && (len > 1)) {
		p++;
		len--;
	}

	SMW_DBG_PRINTF(DEBUG, "Remove leading %zd 0(s)\n", p - *data);

	*data = p;
	*length = len;
}

static int decode_integer(const uint8_t **data, const uint8_t *end,
			  uint8_t **integer, size_t *length)
{
	const uint8_t *p = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !*data || !end || !integer || !length || *data >= end)
		return -1;

	p = *data;

	/* Tag INTEGER */
	if (*p++ != ASN1_TAG_INTEGER)
		return -1;

	/* Length */
	decode_length(&p, end, length);
	if (p + *length > end)
		return -1;

	/* Value */
	remove_leading_zeros(&p, end, length);

	if (*length)
		*integer = (uint8_t *)p;
	else
		*integer = NULL;

	SMW_DBG_PRINTF(DEBUG, "Decode ASN.1 integer\n");
	SMW_DBG_HEX_DUMP(DEBUG, *integer, *length, 4);

	*data = p + *length;

	return 0;
}

int asn1_decode_sequence_integer(const uint8_t *data, size_t data_length,
				 struct asn1_integer sequence[], size_t size)
{
	const uint8_t *p = NULL;
	const uint8_t *end = NULL;
	size_t length = 0;
	size_t i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_length || !sequence || !size)
		return -1;

	p = data;
	end = data + data_length;

	/* Tag SEQUENCE */
	if (*p++ != ASN1_TAG_SEQUENCE)
		return -1;

	/* Length */
	decode_length(&p, end, &length);
	if (p + length > end)
		return -1;

	/* Value */
	for (i = 0; i < size; i++) {
		if (decode_integer(&p, end, &sequence[i].value,
				   &sequence[i].length))
			return -1;
	}

	return 0;
}
