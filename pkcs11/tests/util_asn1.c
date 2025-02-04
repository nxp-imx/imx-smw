// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "local.h"

/*
 * ASN1 TAGs value
 */
#define ASN1_PRINTABLE_STRING  19
#define ASN1_OBJECT_IDENTIFIER 6

int util_to_asn1_string(CK_ATTRIBUTE_PTR attr,
			const struct asn1_ec_curve *curve)
{
	CK_BYTE_PTR bytes = 0;
	size_t str_len = strlen(curve->name);

	if (ADD_OVERFLOW(str_len, 2, &attr->ulValueLen))
		return 0;

	attr->pValue = malloc(attr->ulValueLen);
	if (!attr->pValue)
		return 0;

	bytes = attr->pValue;

	bytes[0] = ASN1_PRINTABLE_STRING;

	if (SET_OVERFLOW(str_len, bytes[1])) {
		free(attr->pValue);
		attr->pValue = NULL_PTR;
		return 0;
	}

	memcpy(&bytes[2], curve->name, attr->ulValueLen - 2);

	return 1;
}

int util_to_asn1_oid(CK_ATTRIBUTE_PTR attr, const struct asn1_ec_curve *curve)
{
	CK_BYTE_PTR bytes = 0;
	size_t oid_len = curve->oid_len;

	if (ADD_OVERFLOW(oid_len, 2, &attr->ulValueLen))
		return 0;

	attr->pValue = malloc(attr->ulValueLen);
	if (!attr->pValue)
		return 0;

	bytes = attr->pValue;

	bytes[0] = ASN1_OBJECT_IDENTIFIER;
	if (SET_OVERFLOW(oid_len, bytes[1])) {
		free(attr->pValue);
		attr->pValue = NULL_PTR;
		return 0;
	}

	memcpy(&bytes[2], curve->oid, attr->ulValueLen - 2);

	return 1;
}

int util_encode_asn1_length(size_t len, uint8_t *out, size_t *outlen)
{
	size_t x = len;
	size_t y = 0;

	if (len == 0 || len > 0xffUL)
		return 0;

	while (x != 0) {
		if (INC_OVERFLOW(y, 1))
			return 0;

		x >>= 8;
	}

	if (!out || *outlen < y)
		return 0;

	x = 0;
	if (len < 128) {
		out[x++] = (unsigned char)len;
	} else if (len <= 0xffUL) {
		out[x++] = 0x81;
		out[x++] = (unsigned char)len;
	}
	*outlen = x;

	return 1;
}
