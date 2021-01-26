/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __UTIL_ASN1_H__
#define __UTIL_ASN1_H__

#include "types.h"

/**
 * struct asn1_curve_def - Definition of ASN1 curve
 * @name: Printable curve name
 * @oid: OID curve
 *
 * Note: The last element must be NULL
 */
struct asn1_curve_def {
	const char *name;
	const CK_BYTE *oid;
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

#endif /* __UTIL_ASN1_H__ */
