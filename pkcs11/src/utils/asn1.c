// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2025 NXP
 */
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "util_asn1.h"

#include "trace.h"

struct asn1_tlv {
	CK_BYTE tag;
	size_t length;
	void *value;
};

/**
 * decode_asn1_length() - Decode the length of a ASN1 string
 * @src: [in/out] Pointer to the string, output the incremented pointer
 * @end: [in] Pointer to the last byte of the string.
 * @outlen: [out] ASN1 string length
 *
 * return:
 * CKR_OK            - Success
 * CKR_DATA_INVALID  - Decoding error
 * CKR_ARGUMENTS_BAD - Bad arguments
 */
static CK_RV decode_asn1_length(uint8_t **src, uint8_t *end, size_t *outlen)
{
	size_t decoded_len = 0;
	size_t nb_octets = 0;
	size_t i = 0;
	uint8_t *p = NULL;

	if (!src || !*src)
		return CKR_ARGUMENTS_BAD;

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
			return CKR_DATA_INVALID;

		decoded_len = 0;
		for (; i < nb_octets; i++)
			decoded_len = (decoded_len << 8) | *p++;
	}

	/*
	 * Check if the decoded length doesn't overflow the string
	 */
	if (*src + decoded_len + 1 > end)
		return CKR_DATA_INVALID;

	if (outlen)
		*outlen = decoded_len;

	*src = p;

	return CKR_OK;
}

/**
 * encode_asn1_length() - Encode a length in ASN1 length format
 * @len: [in] Length to encode
 * @out: [out] Resulting encoding. Output the incremented pointer
 * @outlen: [in/out] Length of the result
 *
 * If the @out is NULL, function calculates the output buffer length and
 * returns CKR_OK.
 *
 * return:
 * CKR_OK                - Success
 * CKR_ARGUMENTS_BAD     - Invalid argument
 * CKR_BUFFER_TOO_SMALL  - Output buffer length too small
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
		return CKR_ARGUMENTS_BAD;

	if (!out) {
		*outlen = nb_octets;
		return CKR_OK;
	}

	if (*outlen < nb_octets) {
		*outlen = nb_octets;
		return CKR_BUFFER_TOO_SMALL;
	}

	p = *out;
	if (!p)
		return CKR_ARGUMENTS_BAD;

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

	return CKR_OK;
}

/**
 * get_tlv() - Get the ASN1 TLV encoded
 * @tlv: TLV structure filled
 * @string: Start of the string to decode
 * @length: String length
 * @offset: Offset in the @string to decode
 *
 * return:
 * CKR_FUNCTION_FAILED - Function failure
 * CKR_OK              - Success
 */
static CK_RV get_tlv(struct asn1_tlv *tlv, CK_BYTE_PTR string, size_t length,
		     size_t offset)
{
	CK_RV ret = CKR_FUNCTION_FAILED;
	CK_BYTE_PTR str = string;
	CK_BYTE_PTR end = str + length;

	if (!str) {
		DBG_TRACE("Error TLV String empty");
		return ret;
	}

	str += offset;

	tlv->tag = *str++;
	ret = decode_asn1_length(&str, end, &tlv->length);

	if (ret == CKR_OK) {
		tlv->value = str;
		DBG_TRACE("ASN1 T=%d L=%zu", tlv->tag, tlv->length);
	}

	return ret;
}

/**
 * get_curve_by_oid() - Get the curve corresponding to the ASN1 oID
 * @tlv: ASN1 TLV defining the oID
 * @curves: List of curves supported
 *
 * return:
 * the reference to the curve found in the list, otherwise NULL
 */
static const struct curve_def *get_curve_by_oid(struct asn1_tlv *tlv,
						const struct curve_def *curves)
{
	const struct curve_def *curve = curves;

	if (!curve || !curve->asn1)
		return NULL;

	while (curve->asn1 && curve->asn1->oid) {
		if (tlv->length == curve->asn1->oid_len) {
			if (!memcmp(curve->asn1->oid, tlv->value, tlv->length))
				return curve;
		}

		curve++;
	}

	return NULL;
}

/**
 * get_curve_by_name() - Get the curve corresponding to the ASN1 string
 * @tlv: ASN1 TLV defining the printable string name
 * @curves: List of curves supported
 *
 * return:
 * the reference to the curve found in the list, otherwise NULL
 */
static const struct curve_def *get_curve_by_name(struct asn1_tlv *tlv,
						 const struct curve_def *curves)
{
	const struct curve_def *curve = curves;

	if (!curve || !curve->asn1)
		return NULL;

	while (curve->asn1 && curve->asn1->name) {
		if (tlv->length == strlen(curve->asn1->name)) {
			if (!memcmp(curve->asn1->name, tlv->value, tlv->length))
				return curve;
		}

		curve++;
	}

	return NULL;
}

CK_RV util_asn1_ec_params_to_curve(const struct curve_def **out_curve,
				   struct libbytes *params,
				   const struct curve_def *curves)
{
	CK_RV ret = CKR_OK;
	struct asn1_tlv tlv = { 0 };
	const struct curve_def *fcurve = NULL;

	/*
	 * Parameters are encoded in ASN1 format:
	 *
	 * Parameters ::= CHOICE {
	 *     ecParameters ECParameters,
	 *     oId CURVES.&id({CurveNames}),
	 *     implicitlyCA NULL,
	 *     curveName PrintableString
	 * }
	 *
	 * Only oId and curveName are supported with the Security
	 * Middleware library.
	 */
	ret = get_tlv(&tlv, params->array, params->number, 0);
	if (ret != CKR_OK)
		return ret;

	switch (tlv.tag) {
	case ASN1_PRINTABLE_STRING:
		fcurve = get_curve_by_name(&tlv, curves);
		if (!fcurve) {
			DBG_TRACE("Printable string Curve not supported");
			ret = CKR_CURVE_NOT_SUPPORTED;
		}
		break;

	case ASN1_OBJECT_IDENTIFIER:
		fcurve = get_curve_by_oid(&tlv, curves);
		if (!fcurve) {
			DBG_TRACE("OID Curve not supported");
			ret = CKR_CURVE_NOT_SUPPORTED;
		}
		break;

	default:
		DBG_TRACE("Tag not supported %d", tlv.tag);
		ret = CKR_ATTRIBUTE_TYPE_INVALID;
	}

	if (ret == CKR_OK && out_curve)
		*out_curve = fcurve;

	return ret;
}

CK_RV util_asn1_curve_to_ec_params(const struct curve_def *curve,
				   struct libbytes *params)
{
	size_t oid_len = 0;
	/*
	 * Parameters are encoded in ASN1 format:
	 *
	 * Parameters ::= CHOICE {
	 *     ecParameters ECParameters,
	 *     oId CURVES.&id({CurveNames}),
	 *     implicitlyCA NULL,
	 *     curveName PrintableString
	 * }
	 *
	 * Prefer to use the curveName to convert curve to params.
	 */
	if (!curve || !params)
		return CKR_ARGUMENTS_BAD;

	oid_len = curve->asn1->oid_len;

	if (ADD_OVERFLOW(oid_len, 2, &params->number))
		return CKR_GENERAL_ERROR;

	params->array = calloc(1, params->number);
	if (!params->array)
		return CKR_HOST_MEMORY;

	params->array[0] = ASN1_OBJECT_IDENTIFIER;

	if (SET_OVERFLOW(oid_len, params->array[1])) {
		free(params->array);
		params->array = NULL_PTR;
		return CKR_GENERAL_ERROR;
	}

	memcpy(&params->array[2], curve->asn1->oid, params->number - 2);

	return CKR_OK;
}

CK_RV util_asn1_encode_octet_string(const uint8_t *in, size_t inlen,
				    uint8_t *out, size_t *outlen)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	uint8_t *p = out;
	size_t len = 0;

	if (!outlen)
		goto end;

	/* Get the number of bytes of the ASN1 length to encode */
	ret = encode_asn1_length(inlen, NULL, &len);
	if (ret != CKR_OK)
		goto end;

	/* Add the octet string tag */
	if (INC_OVERFLOW(len, 1)) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	/* Add the length of the octet string itself */
	if (INC_OVERFLOW(len, inlen)) {
		ret = CKR_ARGUMENTS_BAD;
		goto end;
	}

	if (!out || len > *outlen) {
		*outlen = len;
		if (out)
			ret = CKR_BUFFER_TOO_SMALL;

		goto end;
	}

	/* Encode the header */
	*p++ = ASN1_OCTET_STRING_TAG;
	len--;

	/* Encode the octet-string length */
	ret = encode_asn1_length(inlen, &p, &len);
	if (ret != CKR_OK)
		goto end;

	/* Copy the octet string */
	if (in)
		memcpy(p, in, inlen);

	p += inlen;

	/* Return length */
	if (SUB_OVERFLOW((uintptr_t)p, (uintptr_t)out, outlen))
		ret = CKR_ARGUMENTS_BAD;
	else
		ret = CKR_OK;

end:
	return ret;
}

CK_RV util_asn1_decode_octet_string(uint8_t *in, size_t inlen, uint8_t *out,
				    size_t *outlen)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	size_t len = 0;
	uint8_t *p = in;
	uint8_t *end = in + inlen;

	/* Must have header at least */
	if (!in || inlen < 2 || !outlen)
		goto end;

	/* Check for 0x04 */
	if (*p++ != ASN1_OCTET_STRING_TAG) {
		ret = CKR_DATA_INVALID;
		goto end;
	}

	ret = decode_asn1_length(&p, end, &len);
	if (ret != CKR_OK)
		goto end;

	if (!out || *outlen < len) {
		*outlen = len;
		if (!out)
			ret = CKR_OK;
		else
			ret = CKR_BUFFER_TOO_SMALL;
	} else {
		memcpy(out, p, len);
		ret = CKR_OK;
	}

end:
	return ret;
}

CK_RV util_asn1_get_field_octet_string(uint8_t *in, size_t inlen, uint8_t **out,
				       size_t *outlen)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	uint8_t *p = in;
	uint8_t *end = in + inlen;

	if (!in || !out || !outlen)
		goto end;

	/*
	 * Octet string is encapsulated with a OCTET-STRING tag followed
	 * by the ASN1 length of the octet string buffer.
	 * Length must be at least 2 bytes
	 */
	if (inlen < 2)
		goto end;

	if (*p++ != ASN1_OCTET_STRING_TAG)
		return CKR_DATA_INVALID;

	ret = decode_asn1_length(&p, end, outlen);
	if (ret == CKR_OK)
		*out = p;

end:
	return ret;
}

CK_RV util_asn1_encode_object_id(struct libbytes *out, struct libbytes *in)
{
	CK_RV ret = CKR_OK;
	struct libbytes tmp = { 0 };

	if (!out || !in)
		return CKR_ARGUMENTS_BAD;

	if (!in->number || !in->array)
		return CKR_ARGUMENTS_BAD;

	ret = util_base128_encode(&tmp, in);
	if (ret != CKR_OK)
		return ret;

	out->number = 1 + tmp.number;
	out->array = malloc(out->number);
	if (out->array) {
		out->array[0] = ANSI_ISO_MEMBER_BODY_TAG;
		memcpy(&out->array[1], tmp.array, tmp.number);
	} else {
		ret = CKR_HOST_MEMORY;
	}

	free(tmp.array);

	return ret;
}

CK_RV util_asn1_decode_object_id(struct libbytes *out, struct libbytes *in)
{
	CK_RV ret = CKR_OK;
	unsigned int tag = 0;
	struct libbytes tmp = { 0 };

	if (!out || !in)
		return CKR_ARGUMENTS_BAD;

	if (!in->number || !in->array)
		return CKR_ARGUMENTS_BAD;

	if (in->number < 2)
		return CKR_DATA_INVALID;

	tag = in->array[0];
	/* TAG value first byte can be 0, 1 or 2 */
	tag /= 40;
	if (tag > 2)
		return CKR_DATA_INVALID;

	/* TAG value second byte must be equal to 2 */
	tag = in->array[0] - tag * 40;
	if (tag != 2)
		return CKR_DATA_INVALID;

	tmp.array = &in->array[1];
	tmp.number = in->number - 1;

	ret = util_base128_decode(out, &tmp);

	return ret;
}
