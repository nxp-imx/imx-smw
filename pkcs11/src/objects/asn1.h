/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __ASN1_H__
#define __ASN1_H__

#include "types.h"

#include "asn1_types.h"

/**
 * asn1_ec_params_to_curve() - Convert an EC parameters to a defined EC curve
 * @params: EC Parameters value encoded in ASN1
 * @curves: List of algorithm curves supported
 *
 * return:
 * CKR_CURVE_NOT_SUPPORTED       - Curve is not supported
 * CKR_FUNCTION_FAILED           - Function failure
 * CKR_ATTIBUTE_VALUE_INVALID    - Attribute value is not valid
 * CKR_OK                        - Success
 */
CK_RV asn1_ec_params_to_curve(struct libbytes *params,
			      const struct curve_def *curves);

#endif /* __ASN1_H__ */
