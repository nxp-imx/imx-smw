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
 * get_tlv() - Get the ASN1 TLV encoded
 * @tlv: TLV structure filled
 * @string: Start of the string to decode
 * @offset: Offset in the @string to decode
 *
 * return:
 * CKR_FUNCTION_FAILED - Function failure
 * CKR_OK              - Success
 */
static CK_RV get_tlv(struct asn1_tlv *tlv, CK_BYTE_PTR string, size_t offset)
{
	CK_BYTE_PTR str = string;
	int idx = 0;
	int nb_octets = 0;
	size_t tmp_len = 0;

	if (!str) {
		DBG_TRACE("Error TLV String empty");
		return CKR_FUNCTION_FAILED;
	}

	str += offset;

	tlv->tag = *str++;
	if (!(*str & ASN1_LONG_LENGTH)) {
		tlv->length = *str++;
		goto end;
	}

	/*
	 * If long form of length, first byte bit 8 set.
	 * The first byte bit 7-1 give the number of
	 * bytes coding the length
	 */
	nb_octets = *str++ & ~ASN1_LONG_LENGTH;
	if (nb_octets > (int)sizeof(tlv->length))
		return CKR_FUNCTION_FAILED;

	tlv->length = 0;
	for (idx = nb_octets - 1; idx > 0; idx--, str++) {
		tmp_len = *str;
		tmp_len <<= 8 * idx;
		tlv->length |= tmp_len;
	}

end:
	tlv->value = str;

	DBG_TRACE("ASN1 T=%d L=%zu", tlv->tag, tlv->length);
	return CKR_OK;
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
	ret = get_tlv(&tlv, params->array, 0);
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

static CK_RV encode_asn1_length(size_t len, uint8_t *out, size_t *outlen)
{
	size_t x = len;
	size_t y = 0;

	while (x != 0) {
		if (INC_OVERFLOW(y, 1))
			return CKR_ARGUMENTS_BAD;

		x >>= 8;
	}

	if (y == 0) {
		DBG_TRACE("Nothing to encode");
		return CKR_ARGUMENTS_BAD;
	}

	if (!out || *outlen < y) {
		*outlen = y;
		return CKR_BUFFER_TOO_SMALL;
	}

	x = 0;
	if (len < 128) {
		out[x++] = (unsigned char)len;
	} else if (len <= 0xffUL) {
		out[x++] = 0x81;
		out[x++] = (unsigned char)len;
	}
	*outlen = x;

	return CKR_OK;
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

CK_RV util_asn1_encode_octet_string(const uint8_t *in, size_t inlen,
				    uint8_t *out, size_t *outlen)
{
	CK_RV ret = CKR_OK;
	size_t x = 0;
	size_t len = 0;

	if (!outlen)
		return CKR_ARGUMENTS_BAD;

	/* get the size */
	ret = encode_asn1_length(inlen, NULL, &len);
	if (ret != CKR_BUFFER_TOO_SMALL)
		return ret;

	/* octet string tag */
	if (INC_OVERFLOW(len, 1))
		return CKR_ARGUMENTS_BAD;

	/* octet string len */
	if (INC_OVERFLOW(len, inlen))
		return CKR_ARGUMENTS_BAD;

	if (len > *outlen) {
		*outlen = len;
		return CKR_BUFFER_TOO_SMALL;
	}

	if (!out)
		return CKR_ARGUMENTS_BAD;

	/* encode the header+len */
	x = 0;
	out[x++] = 0x04;

	if (SUB_OVERFLOW(*outlen, x, &len))
		return CKR_ARGUMENTS_BAD;

	ret = encode_asn1_length(inlen, out + x, &len);
	if (ret != CKR_OK)
		return ret;

	if (INC_OVERFLOW(x, len))
		return CKR_ARGUMENTS_BAD;

	/* store octets */
	if (in)
		memcpy(out + x, in, inlen);

	x += inlen;

	/* return length */
	*outlen = x;

	return CKR_OK;
}

CK_RV util_asn1_decode_octet_string(uint8_t *in, size_t inlen, uint8_t *out,
				    size_t *outlen)
{
	CK_RV ret = CKR_OK;
	size_t x = 0;
	size_t y = 0;
	size_t len = 0;

	/* must have header at least */
	if (!in || inlen < 2 || !outlen)
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

	if (INC_OVERFLOW(x, y))
		return CKR_ARGUMENTS_BAD;

	if (len > (inlen - x))
		return CKR_DATA_INVALID;

	if (!out || *outlen < len) {
		*outlen = len;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(out, in + x, len);

	return CKR_OK;
}
