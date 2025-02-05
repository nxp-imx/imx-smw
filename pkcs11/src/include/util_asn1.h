/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2024-2025 NXP
 */

#ifndef __UTIL_ASN1_H__
#define __UTIL_ASN1_H__

#include "types.h"

/**
 * struct asn1_curve_def - Definition of ASN1 curve
 * @name: Printable curve name
 * @oid: OID curve
 * @oid_len: OID curve length
 *
 * Note: The last element must be NULL
 */
struct asn1_curve_def {
	const char *name;
	const CK_BYTE *oid;
	const size_t oid_len;
};

struct dev_curve_def;

/**
 * struct curve_def - Definition of ASN1 vs SMW curves
 * @asm1: ASN1 curve definition
 * @dev: device curve definition
 *
 * Note: The last element must be NULL
 */
struct curve_def {
	const struct asn1_curve_def *asn1;
	const struct dev_curve_def *dev;
};

/* ASN1 Long format length encoding tag */
#define ASN1_LONG_LENGTH BIT(7)

/*
 * ASN1 TAGs value
 */
#define ASN1_PRINTABLE_STRING  19
#define ASN1_OBJECT_IDENTIFIER 6

/**
 * util_asn1_ec_params_to_curve() - Convert EC parameters to a defined EC curve
 * @out_curve: EC curve found (may be NULL)
 * @params: EC Parameters value encoded in ASN1
 * @curves: List of algorithm curves supported
 *
 * Find the EC curve corresponding to the key EC parameters @params and
 * if success and @out_curve not NULL returns the EC curve element from
 * the list of the algorithm curves @curves.
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_ATTRIBUTE_TYPE_INVALID    - Attribute type is not valid
 * CKR_OK                        - Success
 */
CK_RV util_asn1_ec_params_to_curve(const struct curve_def **out_curve,
				   struct libbytes *params,
				   const struct curve_def *curves);

/**
 * util_asn1_curve_to_ec_params() - Convert EC curve to EC parameters
 * @curve: EC curve value
 * @params: EC Parameters value encoded in ASN1
 *
 * return:
 * CKR_ARGUMENTS_BAD             - Bad arguments
 * CKR_GENERAL_ERROR             - Error in conversion
 * CKR_HOST_MEMORY               - Out of memory
 * CKR_OK                        - Success
 */
CK_RV util_asn1_curve_to_ec_params(const struct curve_def *curve,
				   struct libbytes *params);

/**
 * util_asn1_encode_octet_string() -   Store an OCTET STRING
 * @in:       The array of OCTETS to store (one per char)
 * @inlen:    The number of OCTETS to store
 * @out:      [out] The destination for the DER encoded OCTET STRING
 * @outlen:   [in/out] The max size and resulting size of the DER OCTET STRING
 *
 * return:
 * CKR_BUFFER_TOO_SMALL          - Out buffer too small
 * CKR_ARGUMENTS_BAD             - In buffer invalid
 * CKR_OK                        - Success
 */
CK_RV util_asn1_encode_octet_string(const uint8_t *in, size_t inlen,
				    uint8_t *out, size_t *outlen);

/**
 * util_asn1_decode_octet_string() -   Decode an OCTET STRING
 * @in:      The DER encoded OCTET STRING
 * @inlen:   The size of the DER OCTET STRING
 * @out:     [out] The array of octets stored (one per char)
 * @outlen:  [in/out] The number of octets stored
 *
 * return:
 * CKR_DATA_INVALID              - In buffer too small
 * CKR_ARGUMENTS_BAD             - In len invalid
 * CKR_OK                        - Success
 */
CK_RV util_asn1_decode_octet_string(uint8_t *in, size_t inlen, uint8_t *out,
				    size_t *outlen);

#endif /* __UTIL_ASN1_H__ */
