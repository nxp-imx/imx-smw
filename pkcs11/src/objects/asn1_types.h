/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __ASN1_TYPES_H__
#define __ASN1_TYPES_H__

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

/**
 * struct smw_curve_def - Definition of SMW curve
 * @name: Name of the curve type
 * @secuity_size: Security size in bits
 *
 * Note: The last element must be NULL
 */
struct smw_curve_def {
	const char *name;
	const unsigned int security_size;
};

/**
 * struct curve_def - Definition of ASN1 vs SMW curves
 * @asm1: ASN1 curve definition
 * @smw: SMW curve definition
 *
 * Note: The last element must be NULL
 */
struct curve_def {
	const struct asn1_curve_def *asn1;
	const struct smw_curve_def *smw;
};

/* ASN1 Long format length encoding tag */
#define ASN1_LONG_LENGTH BIT(7)

/*
 * ASN1 TAGs value
 */
#define ASN1_PRINTABLE_STRING  19
#define ASN1_OBJECT_IDENTIFIER 6

#endif /* __ASN1_TYPES_H__ */
