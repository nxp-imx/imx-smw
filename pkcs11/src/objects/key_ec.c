// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>

#include "smw_keymgr.h"

#include "asn1_ec_curve.h"

#include "asn1.h"
#include "asn1_types.h"
#include "attributes.h"
#include "key_ec.h"
#include "lib_device.h"
#include "util.h"

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

#define EC_KEY_PUBLIC  BIT(0)
#define EC_KEY_PRIVATE BIT(1)
#define EC_KEY_PAIR    (EC_KEY_PUBLIC | EC_KEY_PRIVATE)

struct key_ec_pair {
	unsigned long long key_id;
	unsigned int type;
	struct libbytes params;
	struct libbytes point_q;     // Public Key point
	struct libbignumber value_d; // Secure Key scalar
};

enum attr_key_ec_public_list {
	PUB_PARAMS = 0,
	PUB_POINT,
};

const struct template_attr attr_key_ec_public[] = {
	[PUB_PARAMS] = { CKA_EC_PARAMS, 0, MUST, attr_to_byte_array },
	[PUB_POINT] = { CKA_EC_POINT, 0, MUST, attr_to_byte_array },
};

enum attr_key_ec_private_list {
	PRIV_PARAMS = 0,
	PRIV_VALUE,
};

const struct template_attr attr_key_ec_private[] = {
	[PRIV_PARAMS] = { CKA_EC_PARAMS, 0, MUST, attr_to_byte_array },
	[PRIV_VALUE] = { CKA_VALUE, 0, MUST, attr_to_bignumber },
};

/**
 * key_ec_allocate() - Allocate and initialize EC keypair
 * @type: Type of Key to allocate *
 *
 * Allocation and set the @type of key to allocate which is:
 *   EC_KEY_PUBLIC
 *   EC_KEY_PRIVATE
 *   EC_KEY_PAIR
 *
 * return:
 * Key allocated if success
 * NULL otherwise
 */
static struct key_ec_pair *key_ec_allocate(unsigned int type)
{
	struct key_ec_pair *key = NULL;

	key = calloc(1, sizeof(*key));

	DBG_TRACE("Allocated a new EC key (%p) of type %d", key, type);

	if (key)
		key->type = type;

	return key;
}

/**
 * key_ec_free() - Free private or public key
 * @key: EC Keypair
 * @type: Type of key private/public to free
 *
 * Free the key's field related to the request @type.
 *
 * Then, if the requested key @type to free is the same of the @key type:
 *    - Delete the key from SMW subsystem if key'id set
 *    - Free the keypair common fields
 *    - Free the keypair object itself
 *
 * Else key is a keypair, hence switch the key type to the remaining
 * key type part not freed.
 */
static void key_ec_free(struct key_ec_pair *key, unsigned int type)
{
	if (!key)
		return;

	switch (type) {
	case EC_KEY_PUBLIC:
		if (key->point_q.array)
			free(key->point_q.array);
		break;

	case EC_KEY_PRIVATE:
		if (key->value_d.value)
			free(key->value_d.value);
		break;
	default:
		return;
	}

	if (key->type == type) {
		if (key->params.array)
			free(key->params.array);

		(void)libdev_delete_key(key->key_id);

		free(key);
	} else {
		key->type &= ~type;
	}
}

void key_ec_public_free(void *obj)
{
	key_ec_free(obj, EC_KEY_PUBLIC);
}

void key_ec_private_free(void *obj)
{
	key_ec_free(obj, EC_KEY_PRIVATE);
}

CK_RV key_ec_public_create(void **obj, struct libattr_list *attrs)
{
	CK_RV ret;
	struct key_ec_pair *new_key;

	new_key = key_ec_allocate(EC_KEY_PUBLIC);
	if (!new_key)
		return CKR_HOST_MEMORY;

	*obj = new_key;

	DBG_TRACE("Create a new EC public key (%p)", new_key);

	ret = attr_get_value(&new_key->params, &attr_key_ec_public[PUB_PARAMS],
			     attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* Verify that curve is supported */
	ret = asn1_ec_params_to_curve(NULL, &new_key->params, ec_curves);
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
	struct key_ec_pair *new_key;

	new_key = key_ec_allocate(EC_KEY_PRIVATE);
	if (!new_key)
		return CKR_HOST_MEMORY;

	*obj = new_key;

	DBG_TRACE("Create a new EC private key (%p)", new_key);

	ret = attr_get_value(&new_key->params,
			     &attr_key_ec_private[PRIV_PARAMS], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	/* Verify that curve is supported */
	ret = asn1_ec_params_to_curve(NULL, &new_key->params, ec_curves);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&new_key->value_d,
			     &attr_key_ec_private[PRIV_VALUE], attrs,
			     NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	return CKR_OK;
}

CK_RV key_ec_keypair_generate(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR mech,
			      void **pub_obj, struct libattr_list *pub_attrs,
			      void **priv_obj, struct libattr_list *priv_attrs)
{
	CK_RV ret;
	struct key_ec_pair *keypair;
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key_desc = { 0 };
	const struct curve_def *key_curve;

	keypair = key_ec_allocate(EC_KEY_PAIR);
	if (!keypair)
		return CKR_HOST_MEMORY;

	*pub_obj = keypair;
	*priv_obj = keypair;

	DBG_TRACE("Generate an EC keypair (%p)", keypair);

	/* Verify the public key attributes */
	ret = attr_get_value(&keypair->params, &attr_key_ec_public[PUB_PARAMS],
			     pub_attrs, NO_OVERWRITE);
	if (ret != CKR_OK)
		return ret;

	ret = asn1_ec_params_to_curve(&key_curve, &keypair->params, ec_curves);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&keypair->point_q, &attr_key_ec_public[PUB_POINT],
			     pub_attrs, MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	/* Verify the private key attributes */
	ret = attr_get_value(&keypair->params,
			     &attr_key_ec_private[PRIV_PARAMS], priv_attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	ret = attr_get_value(&keypair->value_d,
			     &attr_key_ec_private[PRIV_VALUE], priv_attrs,
			     MUST_NOT);
	if (ret != CKR_OK)
		return ret;

	/* Generate the keypair with SMW library */
	key_desc.type_name = key_curve->smw->name;
	key_desc.security_size = key_curve->smw->security_size;
	gen_args.key_descriptor = &key_desc;

	ret = libdev_operate_mechanism(hsession, mech, &gen_args);

	if (ret == CKR_OK) {
		/*
		 * Save the SMW key identifier in private key object
		 */
		keypair->key_id = key_desc.id;
		DBG_TRACE("Key Pair ID 0x%llX", keypair->key_id);
	}

	return ret;
}

CK_RV key_ec_get_id(struct libbytes *id, void *key, size_t prefix_len)
{
	struct key_ec_pair *keypair = key;

	if (!key || !id)
		return CKR_GENERAL_ERROR;

	id->number = prefix_len + sizeof(keypair->key_id);
	id->array = malloc(id->number);
	if (!id->array)
		return CKR_HOST_MEMORY;

	DBG_TRACE("EC Key ID 0x%llX", keypair->key_id);

	TO_CK_BYTES(&id->array[prefix_len], keypair->key_id);

	return CKR_OK;
}
