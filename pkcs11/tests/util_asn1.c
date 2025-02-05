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
#define ASN1_OCTET_STRING_TAG  0x04

#define ASN1_LONG_LENGTH BIT(7)

/**
 * decode_asn1_length() - Decode the length of a ASN1 string
 * @src: [in/out] Pointer to the string, output the incremented pointer
 * @end: [in] Pointer to the last byte of the string.
 * @outlen: [out] ASN1 string length
 *
 * return:
 * 1 - Success
 * else 0
 */
static int decode_asn1_length(CK_BYTE_PTR *src, CK_BYTE_PTR end, size_t *outlen)
{
	CK_ULONG decoded_len = 0;
	size_t nb_octets = 0;
	size_t i = 0;
	CK_BYTE_PTR p = NULL;

	if (!src || !*src)
		return 0;

	p = *src;

	/*
	 * If long form of length, first byte bit 8 set.
	 * The first byte bit 7-1 give the number of
	 * bytes coding the length
	 */
	if (!(*p & ASN1_LONG_LENGTH)) {
		decoded_len = *p++;
	} else {
		nb_octets = *p++ & ~ASN1_LONG_LENGTH;
		if (!nb_octets || nb_octets > sizeof(decoded_len))
			return 0;

		decoded_len = 0;
		for (; i < nb_octets; i++)
			decoded_len = (decoded_len << 8) | *p++;
	}

	/*
	 * Check if the decoded length doesn't overflow the string
	 */
	if (*src + decoded_len + 1 > end)
		return 0;

	if (outlen)
		*outlen = decoded_len;

	*src = p;

	return 1;
}

/**
 * encode_asn1_length() - Encode a length in ASN1 length format
 * @len: [in] Length to encode
 * @out: [out] Resulting encoding. Output the incremented pointer
 * @outlen: [in/out] Length of the result
 *
 * If the @out is NULL, function calculates the output buffer length and
 * returns 0.
 *
 * return:
 * 1 - Success
 * else 0
 */
static CK_RV encode_asn1_length(size_t len, uint8_t **out, size_t *outlen)
{
	uint8_t *p = NULL;
	size_t x = len;
	size_t nb_octets = 1;

	if (x > ASN1_LONG_LENGTH - 1) {
		while (x != 0) {
			if (INC_OVERFLOW(nb_octets, 1))
				return CKR_ARGUMENTS_BAD;

			x >>= 8;
		}
	}

	if (nb_octets > sizeof(*outlen))
		return 0;

	if (!out) {
		*outlen = nb_octets;
		return 1;
	}

	if (*outlen < nb_octets) {
		*outlen = nb_octets;
		return 0;
	}

	p = *out;
	if (!p)
		return 0;

	*outlen = nb_octets;

	nb_octets--;
	if (!nb_octets) {
		*p++ = len & UINT8_MAX;
	} else {
		*p++ = (ASN1_LONG_LENGTH | nb_octets) & UINT8_MAX;

		while (nb_octets--)
			*p++ = (len >> (8 * nb_octets)) & UINT8_MAX;
	}

	*out = p;

	return 1;
}

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

int util_asn1_encode_octet_string(CK_BYTE_PTR in, CK_ULONG inlen, uint8_t *out,
				  size_t *outlen)
{
	CK_RV ret = 0;
	uint8_t *p = NULL;
	size_t len = 0;

	if (!outlen)
		goto end;

	/* Get the number of bytes of the ASN1 length to encode */
	if (!encode_asn1_length(inlen, NULL, &len))
		goto end;

	/* Add the octet string tag */
	if (INC_OVERFLOW(len, 1))
		goto end;

	/* Add the length of the octet string itself */
	if (INC_OVERFLOW(len, inlen))
		goto end;

	if (!out || len > *outlen) {
		*outlen = len;
		if (!out)
			ret = 1;

		goto end;
	}

	*outlen = len;
	p = out;

	/* Encode the header */
	*p++ = ASN1_OCTET_STRING_TAG;
	len--;

	/* Encode the octet-string length */
	if (!encode_asn1_length(inlen, &p, &len))
		goto end;

	/* Copy the octet string */
	if (in)
		memcpy(p, in, inlen);

	p += inlen;

	/* Return length */
	if (!SUB_OVERFLOW((uintptr_t)p, (uintptr_t)out, outlen))
		ret = 1;

end:

	return ret;
}

int util_asn1_get_field_octet_string(CK_BYTE_PTR in, CK_ULONG inlen,
				     CK_BYTE_PTR *out, size_t *outlen)
{
	int ret = 0;
	CK_BYTE_PTR p = in;
	CK_BYTE_PTR end = in + inlen;

	if (!in || !out || !outlen)
		goto end;

	/*
	 * Octet string is encapsulated with a OCTET-STRING tag followed
	 * by the ASN1 length of the octet string buffer.
	 * Length msut be at least 2 bytes
	 */
	if (inlen < 2)
		goto end;

	if (*p++ != ASN1_OCTET_STRING_TAG)
		goto end;

	ret = decode_asn1_length(&p, end, outlen);
	if (ret)
		*out = p;

end:
	return ret;
}
