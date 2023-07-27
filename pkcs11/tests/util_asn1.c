// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */

#include <stdlib.h>
#include <string.h>

#include <asn1_ec_curve.h>

#include "local.h"

/*
 * ASN1 TAGs value
 */
#define ASN1_PRINTABLE_STRING  19
#define ASN1_OBJECT_IDENTIFIER 6

const CK_BYTE prime192v1[] = ASN1_OID_PRIME192;
const CK_BYTE prime256v1[] = ASN1_OID_PRIME256;

int util_to_asn1_string(CK_ATTRIBUTE_PTR attr, const char *str)
{
	CK_BYTE_PTR bytes = 0;
	size_t str_len = strlen(str);

	if (ADD_OVERFLOW(str_len, 2, &attr->ulValueLen))
		return 0;

	attr->pValue = malloc(attr->ulValueLen);
	if (!attr->pValue)
		return 0;

	bytes = attr->pValue;

	bytes[0] = ASN1_PRINTABLE_STRING;

	if (SET_OVERFLOW(str_len, bytes[1])) {
		free(attr->pValue);
		attr->pValue = NULL;
		return 0;
	}

	memcpy(&bytes[2], str, attr->ulValueLen - 2);

	return 1;
}

int util_to_asn1_oid(CK_ATTRIBUTE_PTR attr, const CK_BYTE *oid)
{
	CK_BYTE_PTR bytes = 0;

	attr->ulValueLen = 2 + sizeof(oid);
	attr->pValue = malloc(attr->ulValueLen);
	if (!attr->pValue)
		return 0;

	bytes = attr->pValue;

	bytes[0] = ASN1_OBJECT_IDENTIFIER;
	bytes[1] = sizeof(oid);
	memcpy(&bytes[2], oid, attr->ulValueLen - 2);

	return 1;
}
