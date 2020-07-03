/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __ASN1_EC_CURVE_H__
#define __ASN1_EC_CURVE_H__

/*
 * EC Curve ASN1 Object Identifier codes
 */
/* Prime192v1: 1.2.840.10045.3.1.1 */
#define ASN1_OID_PRIME192                                                      \
	{                                                                      \
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01                 \
	}

/* Prime256v1: 1.2.840.10045.3.1.7 */
#define ASN1_OID_PRIME256                                                      \
	{                                                                      \
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07                 \
	}

/* BrainpoolP160r1: 1.3.36.3.3.2.8.1.1.1 */
#define ASN1_OID_BRAINPOOL_P160R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01           \
	}

/* BrainpoolP160t1: 1.3.36.3.3.2.8.1.1.2 */
#define ASN1_OID_BRAINPOOL_P160T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02           \
	}

/* BrainpoolP192r1: 1.3.36.3.3.2.8.1.1.3 */
#define ASN1_OID_BRAINPOOL_P192R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03           \
	}

/* BrainpoolP192t1: 1.3.36.3.3.2.8.1.1.4 */
#define ASN1_OID_BRAINPOOL_P192T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04           \
	}

/* BrainpoolP224r1: 1.3.36.3.3.2.8.1.1.5 */
#define ASN1_OID_BRAINPOOL_P224R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05           \
	}

/* BrainpoolP224t1: 1.3.36.3.3.2.8.1.1.6 */
#define ASN1_OID_BRAINPOOL_P224T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06           \
	}

/* BrainpoolP256r1: 1.3.36.3.3.2.8.1.1.7 */
#define ASN1_OID_BRAINPOOL_P256R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07           \
	}

/* BrainpoolP256t1: 1.3.36.3.3.2.8.1.1.8 */
#define ASN1_OID_BRAINPOOL_P256T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08           \
	}

/* BrainpoolP320r1: 1.3.36.3.3.2.8.1.1.9 */
#define ASN1_OID_BRAINPOOL_P320R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09           \
	}

/* BrainpoolP320t1: 1.3.36.3.3.2.8.1.1.10 */
#define ASN1_OID_BRAINPOOL_P320T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0A           \
	}

/* BrainpoolP384r1: 1.3.36.3.3.2.8.1.1.11 */
#define ASN1_OID_BRAINPOOL_P384R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B           \
	}

/* BrainpoolP384t1: 1.3.36.3.3.2.8.1.1.12 */
#define ASN1_OID_BRAINPOOL_P384T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0C           \
	}

/* BrainpoolP512r1: 1.3.36.3.3.2.8.1.1.13 */
#define ASN1_OID_BRAINPOOL_P512R1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D           \
	}

/* BrainpoolP512t1: 1.3.36.3.3.2.8.1.1.14 */
#define ASN1_OID_BRAINPOOL_P512T1                                              \
	{                                                                      \
		0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0E           \
	}

#endif /* __ASN1_EC_CURVE_H__ */
