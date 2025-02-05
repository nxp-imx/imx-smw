// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include "smw/names.h"

#include "asn1_ec_curve.h"
#include "libobj_types.h"
#include "util.h"
#include "util_asn1.h"
#include "trace.h"
#include "key_desc.h"

#define EC_ASN1_CURVE(_name)                                                   \
	{                                                                      \
		.name = #_name, .oid = _name, .oid_len = sizeof(_name)         \
	}

const CK_BYTE prime192v1[] = ASN1_OID_PRIME192;
const CK_BYTE prime256v1[] = ASN1_OID_PRIME256;
const CK_BYTE secp224r1[] = ASN1_OID_SEC_P224R1;
const CK_BYTE secp384r1[] = ASN1_OID_SEC_P384R1;
const CK_BYTE secp521r1[] = ASN1_OID_SEC_P521R1;
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
	EC_ASN1_CURVE(prime192v1),	EC_ASN1_CURVE(prime256v1),
	EC_ASN1_CURVE(secp224r1),	EC_ASN1_CURVE(secp384r1),
	EC_ASN1_CURVE(secp521r1),	EC_ASN1_CURVE(brainpoolP160r1),
	EC_ASN1_CURVE(brainpoolP160t1), EC_ASN1_CURVE(brainpoolP192r1),
	EC_ASN1_CURVE(brainpoolP192t1), EC_ASN1_CURVE(brainpoolP224r1),
	EC_ASN1_CURVE(brainpoolP224t1), EC_ASN1_CURVE(brainpoolP256r1),
	EC_ASN1_CURVE(brainpoolP256t1), EC_ASN1_CURVE(brainpoolP320r1),
	EC_ASN1_CURVE(brainpoolP320t1), EC_ASN1_CURVE(brainpoolP384r1),
	EC_ASN1_CURVE(brainpoolP384t1), EC_ASN1_CURVE(brainpoolP512r1),
	EC_ASN1_CURVE(brainpoolP512t1), { 0 }
};

/**
 * struct dev_curve_def - Definition of SMW curve
 * @name: Name of the curve type
 * @secuity_size: Security size in bits
 *
 * Note: The last element must be NULL
 */
struct dev_curve_def {
	smw_key_type_t name;
	const unsigned int security_size;
};

#define EC_SMW_CURVE(_name, _size)                                             \
	{                                                                      \
		.name = SMW_KEY_TYPE_NAME_##_name, .security_size = _size      \
	}

const struct dev_curve_def ec_smw_curves[] = {
	EC_SMW_CURVE(SECP_R1, 192),	 EC_SMW_CURVE(SECP_R1, 256),
	EC_SMW_CURVE(SECP_R1, 224),	 EC_SMW_CURVE(SECP_R1, 384),
	EC_SMW_CURVE(SECP_R1, 521),	 EC_SMW_CURVE(BRAINPOOL_R1, 160),
	EC_SMW_CURVE(BRAINPOOL_T1, 160), EC_SMW_CURVE(BRAINPOOL_R1, 192),
	EC_SMW_CURVE(BRAINPOOL_T1, 192), EC_SMW_CURVE(BRAINPOOL_R1, 224),
	EC_SMW_CURVE(BRAINPOOL_T1, 224), EC_SMW_CURVE(BRAINPOOL_R1, 256),
	EC_SMW_CURVE(BRAINPOOL_T1, 256), EC_SMW_CURVE(BRAINPOOL_R1, 320),
	EC_SMW_CURVE(BRAINPOOL_T1, 320), EC_SMW_CURVE(BRAINPOOL_R1, 384),
	EC_SMW_CURVE(BRAINPOOL_T1, 384), EC_SMW_CURVE(BRAINPOOL_R1, 512),
	EC_SMW_CURVE(BRAINPOOL_T1, 512), { 0 }
};

/*
 * Definition of the ASN1 EC Curves supported (function )
 */

#define EC_CURVE(_asn1, _smw)                                                  \
	{                                                                      \
		.asn1 = _asn1, .dev = _smw                                     \
	}

const struct curve_def ec_curves[] = {
	EC_CURVE(&ec_asn1_curves[0], &ec_smw_curves[0]),
	EC_CURVE(&ec_asn1_curves[1], &ec_smw_curves[1]),
	EC_CURVE(&ec_asn1_curves[2], &ec_smw_curves[2]),
	EC_CURVE(&ec_asn1_curves[3], &ec_smw_curves[3]),
	EC_CURVE(&ec_asn1_curves[4], &ec_smw_curves[4]),
	EC_CURVE(&ec_asn1_curves[5], &ec_smw_curves[5]),
	EC_CURVE(&ec_asn1_curves[6], &ec_smw_curves[6]),
	EC_CURVE(&ec_asn1_curves[7], &ec_smw_curves[7]),
	EC_CURVE(&ec_asn1_curves[8], &ec_smw_curves[8]),
	EC_CURVE(&ec_asn1_curves[9], &ec_smw_curves[9]),
	EC_CURVE(&ec_asn1_curves[10], &ec_smw_curves[10]),
	EC_CURVE(&ec_asn1_curves[11], &ec_smw_curves[11]),
	EC_CURVE(&ec_asn1_curves[12], &ec_smw_curves[12]),
	EC_CURVE(&ec_asn1_curves[13], &ec_smw_curves[13]),
	EC_CURVE(&ec_asn1_curves[14], &ec_smw_curves[14]),
	EC_CURVE(&ec_asn1_curves[15], &ec_smw_curves[15]),
	EC_CURVE(&ec_asn1_curves[16], &ec_smw_curves[16]),
	EC_CURVE(&ec_asn1_curves[17], &ec_smw_curves[17]),
	EC_CURVE(&ec_asn1_curves[18], &ec_smw_curves[18]),
	EC_CURVE(&ec_asn1_curves[19], &ec_smw_curves[19]),
	{ 0 }
};

struct cipher_def {
	CK_KEY_TYPE ck_key_type;
	smw_key_type_t smw_name;
};

#define CIPHERS(_type, _name)                                                  \
	{                                                                      \
		.ck_key_type = _type, .smw_name = SMW_KEY_TYPE_NAME_##_name    \
	}

const struct cipher_def ciphers[] = { CIPHERS(CKK_AES, AES),
				      CIPHERS(CKK_DES, DES),
				      CIPHERS(CKK_DES3, DES3),
				      CIPHERS(CKK_SM4, SM4),
				      { .smw_name = SMW_KEY_TYPE_NAME_NONE } };

struct hmac_def {
	CK_KEY_TYPE ck_key_type;
	smw_key_type_t smw_name;
	smw_attr_algo_t hash_id;
};

#define HMAC(_type, _hash)                                                     \
	{                                                                      \
		.ck_key_type = _type, .smw_name = SMW_KEY_TYPE_NAME_HMAC,      \
		.hash_id = SMW_ATTR_HASH_##_hash                               \
	}

#define HKDF(_type, _name)                                                     \
	{                                                                      \
		.ck_key_type = _type, .smw_name = SMW_KEY_TYPE_NAME_##_name,   \
		.hash_id = SMW_ATTR_HASH_NONE                                  \
	}

const struct hmac_def hmacs[] = { HMAC(CKK_MD5_HMAC, MD5),
				  HMAC(CKK_SHA_1_HMAC, SHA1),
				  HMAC(CKK_SHA224_HMAC, SHA224),
				  HMAC(CKK_SHA256_HMAC, SHA256),
				  HMAC(CKK_SHA384_HMAC, SHA384),
				  HMAC(CKK_SHA512_HMAC, SHA512),
				  HMAC(CKK_SHA3_224_HMAC, SHA3_224),
				  HMAC(CKK_SHA3_256_HMAC, SHA3_256),
				  HMAC(CKK_SHA3_384_HMAC, SHA3_384),
				  HMAC(CKK_SHA3_512_HMAC, SHA3_512),
				  HKDF(CKK_HKDF, HKDF_IKM),
				  { .smw_name = SMW_KEY_TYPE_NAME_NONE } };

static bool get_cipher_key_from_smw(struct libobj_obj *obj,
				    struct smw_key_descriptor *desc, CK_RV *ret)
{
	const struct cipher_def *cipher = ciphers;
	struct libobj_key_cipher *key = get_subkey_from(obj);
	CK_KEY_TYPE key_type = 0;

	while (cipher->smw_name != SMW_KEY_TYPE_NAME_NONE) {
		if (desc->type_name == cipher->smw_name) {
			key_type = cipher->ck_key_type;
			break;
		}

		cipher++;
	};

	if (cipher->smw_name == SMW_KEY_TYPE_NAME_NONE)
		return false;

	set_key_type(obj, key_type);
	key->value_len = desc->security_size / 8;

	*ret = CKR_OK;

	return true;
}

static CK_RV get_cipher_type_from_pkcs(smw_key_type_t *key_type_name,
				       CK_KEY_TYPE ck_key_type)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	const struct cipher_def *cipher = ciphers;

	while (cipher->smw_name != SMW_KEY_TYPE_NAME_NONE) {
		if (ck_key_type == cipher->ck_key_type) {
			*key_type_name = cipher->smw_name;
			ret = CKR_OK;
			break;
		}

		cipher++;
	};

	return ret;
}

static bool get_hmac_key_from_smw(struct libobj_obj *obj,
				  struct smw_key_descriptor *desc,
				  struct smw_key_attributes *attributes,
				  CK_RV *ret)
{
	const struct hmac_def *hmac = hmacs;
	smw_attr_algo_t hash_id = SMW_ATTR_HASH_NONE;
	struct libobj_key_hmac *key = get_subkey_from(obj);
	CK_KEY_TYPE key_type = 0;

	hash_id = SMW_ATTR_GET_HASH(attributes->permitted_algo);

	while (hmac->smw_name != SMW_KEY_TYPE_NAME_NONE) {
		if (desc->type_name == hmac->smw_name &&
		    hash_id == hmac->hash_id) {
			key_type = hmac->ck_key_type;
			break;
		}

		hmac++;
	};

	if (hmac->smw_name == SMW_KEY_TYPE_NAME_NONE)
		return false;

	set_key_type(obj, key_type);
	key->value_len = desc->security_size / 8;

	*ret = CKR_OK;

	return true;
}

static CK_RV get_hmac_type_from_pkcs(smw_key_type_t *key_type_name,
				     CK_KEY_TYPE ck_key_type)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	const struct hmac_def *hmac = hmacs;

	while (hmac->smw_name != SMW_KEY_TYPE_NAME_NONE) {
		if (ck_key_type == hmac->ck_key_type) {
			*key_type_name = hmac->smw_name;
			ret = CKR_OK;
			break;
		}

		hmac++;
	};

	return ret;
}

static bool get_ec_key_from_smw(struct libobj_obj *obj,
				struct smw_key_descriptor *desc, CK_RV *ret)
{
	const struct curve_def *curve = ec_curves;
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	while (curve->dev->name) {
		if (desc->type_name == curve->dev->name &&
		    desc->security_size == curve->dev->security_size)
			break;

		curve++;
	}

	if (!curve->dev->name)
		return false;

	set_key_type(obj, CKK_EC);

	/* Convert the curve to EC params */
	*ret = util_asn1_curve_to_ec_params(curve, &key->params);

	return true;
}

static CK_RV get_ec_curve_from_pkcs(struct smw_key_descriptor *desc,
				    struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	const struct curve_def *curve = NULL;
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	/* Verify that curve is supported */
	ret = util_asn1_ec_params_to_curve(&curve, &key->params, ec_curves);
	if (ret == CKR_OK) {
		desc->type_name = curve->dev->name;
		desc->security_size = curve->dev->security_size;
	}

	return ret;
}

static bool get_rsa_key_from_smw(struct libobj_obj *obj,
				 struct smw_key_descriptor *desc, CK_RV *ret)
{
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);

	if (desc->type_name != SMW_KEY_TYPE_NAME_RSA)
		return false;

	set_key_type(obj, CKK_RSA);

	/*
	 * Modulus length defines the RSA security size
	 */
	key->modulus_length = desc->security_size;

	*ret = CKR_OK;

	return true;
}

static CK_RV get_rsa_from_pkcs(struct smw_key_descriptor *desc)
{
	desc->type_name = SMW_KEY_TYPE_NAME_RSA;

	return CKR_OK;
}

static CK_RV ec_key_desc(struct smw_key_descriptor *desc,
			 struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_ec_pair *key = get_subkey_from(obj);

	/* Verify that curve is supported */
	ret = get_ec_curve_from_pkcs(desc, obj);
	if (ret != CKR_OK)
		return ret;

	/*
	 * If SMW key's descriptor buffer field is set, setup it
	 * with the EC key object's buffer
	 */
	if (desc->buffer) {
		smw_key = &desc->buffer->gen;
		/*
		 * Remove the header of the Public Buffer
		 * DER ANSI X9.62 uncompress code byte
		 */
		if (key->point_q.array) {
			smw_key->public_data = key->point_q.array + 1;
			if (SUB_OVERFLOW(key->point_q.number, 1,
					 &smw_key->public_length))
				ret = CKR_ARGUMENTS_BAD;
		}

		smw_key->private_data = key->value_d.value;

		if (SET_OVERFLOW(key->value_d.length, smw_key->private_length))
			ret = CKR_ARGUMENTS_BAD;
	}

	return ret;
}

static CK_RV cipher_key_desc(struct smw_key_descriptor *desc,
			     struct libobj_obj *obj)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_cipher *key = get_subkey_from(obj);
	CK_KEY_TYPE key_type = get_key_type(obj);
	size_t key_length = key->value_len;

	switch (key_type) {
	case CKK_DES:
		desc->security_size = 56;
		break;

	case CKK_DES3:
		desc->security_size = 168;
		break;

	case CKK_AES:
		if (key_length != 16 && key_length != 24 && key_length != 32)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		desc->security_size = key_length * 8;
		break;

	case CKK_SM4:
		if (key_length != 16)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		desc->security_size = key_length * 8;
		break;

	default:
		/* This case should never occurred, but ... */
		return ret;
	}

	ret = get_cipher_type_from_pkcs(&desc->type_name, key_type);
	if (ret != CKR_OK)
		return ret;

	/*
	 * If SMW key's descriptor buffer field is set, setup it
	 * with the Cipher key object's buffer
	 */
	if (desc->buffer) {
		smw_key = &desc->buffer->gen;
		smw_key->private_data = key->value.array;
		if (SET_OVERFLOW(key->value.number, smw_key->private_length))
			return CKR_ARGUMENTS_BAD;
	}

	return ret;
}

static CK_RV hmac_key_desc(struct smw_key_descriptor *desc,
			   struct libobj_obj *obj)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_hmac *key = get_subkey_from(obj);
	CK_KEY_TYPE key_type = get_key_type(obj);
	size_t key_length = key->value_len;

	switch (key_type) {
	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		if (MUL_OVERFLOW(key_length, 8, &desc->security_size))
			return CKR_ARGUMENTS_BAD;

		break;

	default:
		/* This case should never occurred, but ... */
		return ret;
	}

	ret = get_hmac_type_from_pkcs(&desc->type_name, key_type);
	if (ret != CKR_OK)
		return ret;

	/*
	 * If SMW key's descriptor buffer field is set, setup it
	 * with the Cipher key object's buffer
	 */
	if (desc->buffer) {
		smw_key = &desc->buffer->gen;
		smw_key->private_data = key->value.array;
		if (SET_OVERFLOW(key->value.number, smw_key->private_length))
			return CKR_ARGUMENTS_BAD;
	}

	return ret;
}

static CK_RV rsa_key_desc(struct smw_key_descriptor *desc,
			  struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct smw_keypair_rsa *smw_key = NULL;
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);
	size_t security_size = 0;

	ret = get_rsa_from_pkcs(desc);
	if (ret != CKR_OK)
		return ret;

	/*
	 * Modulus length defines the RSA security size
	 * If key field modulus_length is defined, this is
	 * by definition a key generation.
	 * Else, the object key modulus length buffer defines
	 * the key security size
	 */
	if (key->modulus_length)
		security_size = key->modulus_length;
	else if (key->modulus.value)
		security_size = util_get_bignum_bits(&key->modulus);

	if (!security_size)
		return CKR_ATTRIBUTE_VALUE_INVALID;

	if (SET_OVERFLOW(security_size, desc->security_size))
		return CKR_ARGUMENTS_BAD;

	/*
	 * If SMW key's descriptor buffer field is set, setup it
	 * with the RSA key object's buffer
	 */
	if (desc->buffer) {
		smw_key = &desc->buffer->rsa;
		smw_key->modulus = key->modulus.value;
		if (SET_OVERFLOW(key->modulus.length, smw_key->modulus_length))
			return CKR_ARGUMENTS_BAD;

		smw_key->public_data = key->pub_exp.value;
		if (SET_OVERFLOW(key->pub_exp.length, smw_key->public_length))
			return CKR_ARGUMENTS_BAD;

		smw_key->private_data = key->priv_exp.value;
		if (SET_OVERFLOW(key->priv_exp.length, smw_key->private_length))
			return CKR_ARGUMENTS_BAD;

		smw_key->public_exponent = key->pub_exp.value;
		if (SET_OVERFLOW(key->pub_exp.length,
				 smw_key->public_exponent_length))
			return CKR_ARGUMENTS_BAD;
	}

	return CKR_OK;
}

CK_RV key_desc_smw_to_pkcs11(struct libobj_obj *obj,
			     struct smw_get_key_attributes_args *attributes)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	struct smw_key_descriptor *key_desc = NULL;
	struct smw_key_attributes *key_attr = NULL;

	key_desc = attributes->key_descriptor;
	key_attr = &attributes->key_attributes;

	/* Find and set the key type */
	if (get_cipher_key_from_smw(obj, key_desc, &ret))
		goto end;
	else if (get_hmac_key_from_smw(obj, key_desc, key_attr, &ret))
		goto end;
	else if (get_rsa_key_from_smw(obj, key_desc, &ret))
		goto end;

	get_ec_key_from_smw(obj, key_desc, &ret);

end:
	return ret;
}

CK_RV key_desc_setup(struct smw_key_descriptor *desc, struct libobj_obj *obj)
{
	CK_RV ret = CKR_FUNCTION_FAILED;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		ret = cipher_key_desc(desc, obj);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		ret = hmac_key_desc(desc, obj);
		break;

	case CKK_EC:
		ret = ec_key_desc(desc, obj);
		break;

	case CKK_RSA:
		ret = rsa_key_desc(desc, obj);
		break;

	default:
		break;
	}

	return ret;
}

void key_desc_copy_key_id(struct libobj_obj *obj,
			  struct smw_key_descriptor *desc)
{
	struct libobj_key_cipher *cipher_key = NULL;
	struct libobj_key_hmac *hmac_key = NULL;
	struct libobj_key_ec_pair *ec_key = NULL;
	struct libobj_key_rsa_pair *rsa_key = NULL;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		cipher_key = get_subkey_from(obj);
		cipher_key->key_id = desc->id;
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		hmac_key = get_subkey_from(obj);
		hmac_key->key_id = desc->id;
		break;

	case CKK_EC:
		ec_key = get_subkey_from(obj);
		ec_key->key_id = desc->id;
		break;

	case CKK_RSA:
		rsa_key = get_subkey_from(obj);
		rsa_key->key_id = desc->id;
		break;

	default:
		break;
	}
}

static int set_key_buffer(CK_BYTE_PTR key_buffer, size_t key_length,
			  struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;

	struct smw_keypair_gen *smw_key = NULL;

	if (desc->buffer) {
		smw_key = &desc->buffer->gen;
		smw_key->public_data = key_buffer;
		if (!SET_OVERFLOW(key_length, smw_key->public_length))
			ret = CKR_OK;
	}

	return ret;
}

int base_key_desc_setup(struct libobj_obj *obj, struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_OK;

	struct libobj_key_cipher *cipher_key = NULL;
	struct libobj_key_hmac *hmac_key = NULL;
	CK_KEY_TYPE key_type = get_key_type(obj);

	switch (key_type) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		cipher_key = get_subkey_from(obj);
		desc->id = cipher_key->key_id;
		if (desc->id == 0) {
			desc->type_name = SMW_KEY_TYPE_NAME_RAW;
			ret = set_key_buffer(cipher_key->value.array,
					     cipher_key->value.number, desc);
		}

		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		hmac_key = get_subkey_from(obj);
		desc->id = hmac_key->key_id;
		if (desc->id == 0) {
			desc->type_name = SMW_KEY_TYPE_NAME_RAW;
			ret = set_key_buffer(hmac_key->value.array,
					     hmac_key->value.number, desc);
		}

		break;

	case CKK_EC:
		ret = ec_key_desc(desc, obj);

		break;

	default:
		ret = CKR_ARGUMENTS_BAD;
		break;
	}

	return ret;
}

CK_RV derived_key_desc_setup(struct smw_derived_key_descriptor *desc,
			     struct libobj_obj *obj)
{
	int status = CKR_ATTRIBUTE_VALUE_INVALID;

	struct libobj_key_cipher *cipher_key = NULL;
	struct libobj_key_hmac *hmac_key = NULL;
	CK_KEY_TYPE key_type = get_key_type(obj);
	size_t key_length = 0;

	switch (key_type) {
	case CKK_DES:
		desc->security_size = 56;

		status = get_cipher_type_from_pkcs(&desc->type_name, key_type);

		break;

	case CKK_DES3:
		desc->security_size = 168;

		status = get_cipher_type_from_pkcs(&desc->type_name, key_type);

		break;

	case CKK_AES:
		cipher_key = get_subkey_from(obj);
		key_length = cipher_key->value_len;
		if (key_length != 16 && key_length != 24 && key_length != 32)
			goto exit;

		desc->security_size = key_length * 8;

		status = get_cipher_type_from_pkcs(&desc->type_name, key_type);

		break;

	case CKK_SM4:
		cipher_key = get_subkey_from(obj);
		key_length = cipher_key->value_len;
		if (key_length != 16)
			goto exit;

		desc->security_size = key_length * 8;

		status = get_cipher_type_from_pkcs(&desc->type_name, key_type);

		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		hmac_key = get_subkey_from(obj);
		key_length = hmac_key->value_len;

		if (MUL_OVERFLOW(key_length, 8, &desc->security_size)) {
			status = CKR_ARGUMENTS_BAD;
			goto exit;
		}

		status = get_hmac_type_from_pkcs(&desc->type_name, key_type);

		break;

	default:
		status = CKR_FUNCTION_FAILED;
	}

exit:
	return status;
}

int get_key_desc_key_id(struct libobj_obj *obj, struct smw_key_descriptor *desc)
{
	int status = CKR_OK;

	struct libobj_key_cipher *cipher_key = NULL;
	struct libobj_key_hmac *hmac_key = NULL;
	struct libobj_key_ec_pair *ec_key = NULL;
	struct libobj_key_rsa_pair *rsa_key = NULL;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		cipher_key = get_subkey_from(obj);
		desc->id = cipher_key->key_id;
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		hmac_key = get_subkey_from(obj);
		desc->id = hmac_key->key_id;
		break;

	case CKK_EC:
		ec_key = get_subkey_from(obj);
		desc->id = ec_key->key_id;
		break;

	case CKK_RSA:
		rsa_key = get_subkey_from(obj);
		desc->id = rsa_key->key_id;
		break;

	default:
		status = CKR_ARGUMENTS_BAD;
		break;
	}

	return status;
}

void derived_key_desc_copy_key_id(struct libobj_obj *obj,
				  struct smw_derived_key_descriptor *desc)
{
	struct libobj_key_cipher *cipher_key = NULL;
	struct libobj_key_hmac *hmac_key = NULL;

	switch (get_key_type(obj)) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		cipher_key = get_subkey_from(obj);
		cipher_key->key_id = desc->id;
		DBG_TRACE("Cipher key ID = %d", cipher_key->key_id);
		break;

	case CKK_MD5_HMAC:
	case CKK_SHA_1_HMAC:
	case CKK_SHA224_HMAC:
	case CKK_SHA256_HMAC:
	case CKK_SHA384_HMAC:
	case CKK_SHA512_HMAC:
	case CKK_SHA3_224_HMAC:
	case CKK_SHA3_256_HMAC:
	case CKK_SHA3_384_HMAC:
	case CKK_SHA3_512_HMAC:
	case CKK_HKDF:
		hmac_key = get_subkey_from(obj);
		hmac_key->key_id = desc->id;
		DBG_TRACE("HMAC key ID = %d", hmac_key->key_id);
		break;

	default:
		DBG_TRACE("Non matched key type");
		return;
	}
}
