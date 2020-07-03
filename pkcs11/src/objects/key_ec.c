// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>

#include "asn1_ec_curve.h"

#include "asn1.h"
#include "asn1_types.h"
#include "attributes.h"
#include "key_ec.h"

#include "trace.h"

#define EC_ASN1_CURVE(name)                                                    \
	{                                                                      \
#name, name                                                    \
	}

const CK_BYTE prime192v1[] = ASN1_OID_PRIME192;
const CK_BYTE prime256v1[] = ASN1_OID_PRIME256;
const CK_BYTE brainpoolP160r1[] = ASN1_OID_BRAINPOOL_P160R1;
const CK_BYTE brainpoolP160t1[] = ASN1_OID_BRAINPOOL_P160T1;
const CK_BYTE brainpoolP192r1[] = ASN1_OID_BRAINPOOL_P192R1;
const CK_BYTE brainpoolP192t1[] = ASN1_OID_BRAINPOOL_P192T1;
const CK_BYTE brainpoolP224r1[] = ASN1_OID_BRAINPOOL_P224R1;
const CK_BYTE brainpoolP224t1[] = ASN1_OID_BRAINPOOL_P224T1;
const CK_BYTE brainpoolP256r1[] = ASN1_OID_BRAINPOOL_P256R1;
const CK_BYTE brainpoolP256t1[] = ASN1_OID_BRAINPOOL_P256T1;
const CK_BYTE brainpoolP320r1[] = ASN1_OID_BRAINPOOL_P320R1;
const CK_BYTE brainpoolP320t1[] = ASN1_OID_BRAINPOOL_P320T1;
const CK_BYTE brainpoolP384r1[] = ASN1_OID_BRAINPOOL_P384R1;
const CK_BYTE brainpoolP384t1[] = ASN1_OID_BRAINPOOL_P384T1;
const CK_BYTE brainpoolP512r1[] = ASN1_OID_BRAINPOOL_P512R1;
const CK_BYTE brainpoolP512t1[] = ASN1_OID_BRAINPOOL_P512T1;

const struct asn1_curve_def ec_asn1_curves[] = {
	EC_ASN1_CURVE(prime192v1),
	EC_ASN1_CURVE(prime256v1),
	EC_ASN1_CURVE(brainpoolP160r1),
	EC_ASN1_CURVE(brainpoolP160t1),
	EC_ASN1_CURVE(brainpoolP192r1),
	EC_ASN1_CURVE(brainpoolP192t1),
	EC_ASN1_CURVE(brainpoolP224r1),
	EC_ASN1_CURVE(brainpoolP224t1),
	EC_ASN1_CURVE(brainpoolP256r1),
	EC_ASN1_CURVE(brainpoolP256t1),
	EC_ASN1_CURVE(brainpoolP320r1),
	EC_ASN1_CURVE(brainpoolP320t1),
	EC_ASN1_CURVE(brainpoolP384r1),
	EC_ASN1_CURVE(brainpoolP384t1),
	EC_ASN1_CURVE(brainpoolP512r1),
	EC_ASN1_CURVE(brainpoolP512t1),
	{ 0 },
};

const struct smw_curve_def ec_smw_curves[] = {
	{ "NIST", 192 },
	{ "NIST", 256 },
	{ "BRAINPOOL_R1", 160 },
	{ "BRAINPOOL_T1", 160 },
	{ "BRAINPOOL_R1", 192 },
	{ "BRAINPOOL_T1", 192 },
	{ "BRAINPOOL_R1", 224 },
	{ "BRAINPOOL_T1", 224 },
	{ "BRAINPOOL_R1", 256 },
	{ "BRAINPOOL_T1", 256 },
	{ "BRAINPOOL_R1", 320 },
	{ "BRAINPOOL_T1", 320 },
	{ "BRAINPOOL_R1", 384 },
	{ "BRAINPOOL_T1", 384 },
	{ "BRAINPOOL_R1", 512 },
	{ "BRAINPOOL_T1", 512 },
	{ 0 },
};

/*
 * Definition of the ASN1 EC Curves supported (function )
 */
const struct curve_def ec_curves[] = {
	{ &ec_asn1_curves[0], &ec_smw_curves[0] },
	{ &ec_asn1_curves[1], &ec_smw_curves[1] },
	{ &ec_asn1_curves[2], &ec_smw_curves[2] },
	{ &ec_asn1_curves[3], &ec_smw_curves[3] },
	{ &ec_asn1_curves[4], &ec_smw_curves[4] },
	{ &ec_asn1_curves[5], &ec_smw_curves[5] },
	{ &ec_asn1_curves[6], &ec_smw_curves[6] },
	{ &ec_asn1_curves[7], &ec_smw_curves[7] },
	{ &ec_asn1_curves[8], &ec_smw_curves[8] },
	{ &ec_asn1_curves[9], &ec_smw_curves[9] },
	{ &ec_asn1_curves[10], &ec_smw_curves[10] },
	{ &ec_asn1_curves[11], &ec_smw_curves[11] },
	{ &ec_asn1_curves[12], &ec_smw_curves[12] },
	{ &ec_asn1_curves[13], &ec_smw_curves[13] },
	{ &ec_asn1_curves[14], &ec_smw_curves[14] },
	{ &ec_asn1_curves[15], &ec_smw_curves[15] },
	{ &ec_asn1_curves[16], &ec_smw_curves[16] },
	{ 0 },
};

struct key_ec_public {
	struct libbytes params;
	struct libbytes point_q;
};

enum attr_key_ec_public_list {
	PUB_PARAMS = 0,
	PUB_POINT,
};

struct template_attr attr_key_ec_public[] = {
	[PUB_PARAMS] = { CKA_EC_PARAMS, 0, MUST, attr_to_byte_array },
	[PUB_POINT] = { CKA_EC_POINT, 0, MUST, attr_to_byte_array },
};

struct key_ec_private {
	struct libbytes params;
	struct libbignumber value_d;
};

enum attr_key_ec_private_list {
	PRIV_PARAMS = 0,
	PRIV_VALUE,
};

struct template_attr attr_key_ec_private[] = {
	[PRIV_PARAMS] = { CKA_EC_PARAMS, 0, MUST, attr_to_byte_array },
	[PRIV_VALUE] = { CKA_VALUE, 0, MUST, attr_to_bignumber },
};

/**
 * key_ec_public_allocate() - Allocate and initialize EC public key
 * @key: Key allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV key_ec_public_allocate(struct key_ec_public **key)
{
	*key = calloc(1, sizeof(**key));
	if (!*key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Allocated a new public EC key (%p)", *key);

	return CKR_OK;
}

/**
 * key_ec_private_allocate() - Allocate and initialize EC private key
 * @key: Key allocated
 *
 * return:
 * CKR_HOST_MEMORY - Out of memory
 * CKR_OK          - Success
 */
static CK_RV key_ec_private_allocate(struct key_ec_private **key)
{
	*key = calloc(1, sizeof(**key));
	if (!*key)
		return CKR_HOST_MEMORY;

	DBG_TRACE("Allocated a new private EC key (%p)", *key);

	return CKR_OK;
}

void key_ec_public_free(void *obj)
{
	struct key_ec_public *key = obj;

	if (!key)
		return;

	if (key->params.array)
		free(key->params.array);

	if (key->point_q.array)
		free(key->point_q.array);

	free(key);
}

void key_ec_private_free(void *obj)
{
	struct key_ec_private *key = obj;

	if (!key)
		return;

	if (key->params.array)
		free(key->params.array);

	if (key->value_d.value)
		free(key->value_d.value);

	free(key);
}

CK_RV key_ec_public_create(void **obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct key_ec_public *new_key;

	ret = key_ec_public_allocate(&new_key);
	if (ret != CKR_OK)
		return ret;

	*obj = new_key;

	DBG_TRACE("Create a new EC public key (%p)", new_key);

	ret = attr_get_value(&new_key->params, &attr_key_ec_public[PUB_PARAMS],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* Verify that curve is supported */
	ret = asn1_ec_params_to_curve(&new_key->params, ec_curves);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->point_q, &attr_key_ec_public[PUB_POINT],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	return CKR_OK;
}

CK_RV key_ec_private_create(void **obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct key_ec_private *new_key;

	ret = key_ec_private_allocate(&new_key);
	if (ret != CKR_OK)
		return ret;

	*obj = new_key;

	DBG_TRACE("Create a new EC private key (%p)", new_key);

	ret = attr_get_value(&new_key->params,
			     &attr_key_ec_private[PRIV_PARAMS], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* Verify that curve is supported */
	ret = asn1_ec_params_to_curve(&new_key->params, ec_curves);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->value_d,
			     &attr_key_ec_private[PRIV_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	return CKR_OK;
}
