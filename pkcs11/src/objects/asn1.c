// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include <string.h>

#include "util.h"

#include "asn1.h"

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
	int idx;
	int nb_octets;
	size_t tmp_len;

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
		if (tlv->length == sizeof(curve->asn1->oid)) {
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

CK_RV asn1_ec_params_to_curve(struct libbytes *params,
			      const struct curve_def *curves)
{
	CK_RV ret;
	struct asn1_tlv tlv;
	const struct curve_def *fcurve;

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

	return ret;
}
