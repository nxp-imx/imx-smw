// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include <stdlib.h>
#include <string.h>

#include "smw/names.h"

#include "asn1_ec_curve.h"
#include "libobj_types.h"
#include "util.h"
#include "util_asn1.h"
#include "key_desc.h"

/*
 * Define key descriptor manipulation to convert from SMW to PKCS11 or
 * the opposite
 * OP_KEY_DESC_SET_xxx: Convert PKCS11 to SMW descriptor
 * OP_KEY_DESC_GET_xxx: Convert SMW descriptor to PKCS11
 */
#define OP_KEY_DESC_SET_KEY_TYPE      BIT(0)
#define OP_KEY_DESC_SET_SECURITY_SIZE BIT(1)
#define OP_KEY_DESC_SET_BUFFER	      BIT(2)
#define OP_KEY_DESC_SET_ALL	      BIT_MASK(8)
#define OP_KEY_DESC_GET_KEY_TYPE      BIT(8)
#define OP_KEY_DESC_GET_SECURITY_SIZE BIT(9)
#define OP_KEY_DESC_GET_ALL	      (BIT_MASK(16) & ~OP_KEY_DESC_SET_ALL)

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
const CK_BYTE edwards25519[] = ASN1_OID_ED25519;
const CK_BYTE edwards448[] = ASN1_OID_ED448;

enum name_ec_key {
	EC_PRIME192V1,
	EC_PRIME256V1,
	EC_SECP224R1,
	EC_SECP384R1,
	EC_SECP521R1,
	EC_BRAINPOOL160R1,
	EC_BRAINPOOL160T1,
	EC_BRAINPOOL192R1,
	EC_BRAINPOOL192T1,
	EC_BRAINPOOL224R1,
	EC_BRAINPOOL224T1,
	EC_BRAINPOOL256R1,
	EC_BRAINPOOL256T1,
	EC_BRAINPOOL320R1,
	EC_BRAINPOOL320T1,
	EC_BRAINPOOL384R1,
	EC_BRAINPOOL384T1,
	EC_BRAINPOOL512R1,
	EC_BRAINPOOL512T1,
	EC_ED25519,
	EC_ED448,
	EC_NB_KEY_NAME
};

const struct asn1_curve_def ec_asn1_curves[] = {
	[EC_PRIME192V1] = EC_ASN1_CURVE(prime192v1),
	[EC_PRIME256V1] = EC_ASN1_CURVE(prime256v1),
	[EC_SECP224R1] = EC_ASN1_CURVE(secp224r1),
	[EC_SECP384R1] = EC_ASN1_CURVE(secp384r1),
	[EC_SECP521R1] = EC_ASN1_CURVE(secp521r1),
	[EC_BRAINPOOL160R1] = EC_ASN1_CURVE(brainpoolP160r1),
	[EC_BRAINPOOL160T1] = EC_ASN1_CURVE(brainpoolP160t1),
	[EC_BRAINPOOL192R1] = EC_ASN1_CURVE(brainpoolP192r1),
	[EC_BRAINPOOL192T1] = EC_ASN1_CURVE(brainpoolP192t1),
	[EC_BRAINPOOL224R1] = EC_ASN1_CURVE(brainpoolP224r1),
	[EC_BRAINPOOL224T1] = EC_ASN1_CURVE(brainpoolP224t1),
	[EC_BRAINPOOL256R1] = EC_ASN1_CURVE(brainpoolP256r1),
	[EC_BRAINPOOL256T1] = EC_ASN1_CURVE(brainpoolP256t1),
	[EC_BRAINPOOL320R1] = EC_ASN1_CURVE(brainpoolP320r1),
	[EC_BRAINPOOL320T1] = EC_ASN1_CURVE(brainpoolP320t1),
	[EC_BRAINPOOL384R1] = EC_ASN1_CURVE(brainpoolP384r1),
	[EC_BRAINPOOL384T1] = EC_ASN1_CURVE(brainpoolP384t1),
	[EC_BRAINPOOL512R1] = EC_ASN1_CURVE(brainpoolP512r1),
	[EC_BRAINPOOL512T1] = EC_ASN1_CURVE(brainpoolP512t1),
	[EC_ED25519] = EC_ASN1_CURVE(edwards25519),
	[EC_ED448] = EC_ASN1_CURVE(edwards448),
	[EC_NB_KEY_NAME] = { 0 }
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
	[EC_PRIME192V1] = EC_SMW_CURVE(SECP_R1, 192),
	[EC_PRIME256V1] = EC_SMW_CURVE(SECP_R1, 256),
	[EC_SECP224R1] = EC_SMW_CURVE(SECP_R1, 224),
	[EC_SECP384R1] = EC_SMW_CURVE(SECP_R1, 384),
	[EC_SECP521R1] = EC_SMW_CURVE(SECP_R1, 521),
	[EC_BRAINPOOL160R1] = EC_SMW_CURVE(BRAINPOOL_R1, 160),
	[EC_BRAINPOOL160T1] = EC_SMW_CURVE(BRAINPOOL_T1, 160),
	[EC_BRAINPOOL192R1] = EC_SMW_CURVE(BRAINPOOL_R1, 192),
	[EC_BRAINPOOL192T1] = EC_SMW_CURVE(BRAINPOOL_T1, 192),
	[EC_BRAINPOOL224R1] = EC_SMW_CURVE(BRAINPOOL_R1, 224),
	[EC_BRAINPOOL224T1] = EC_SMW_CURVE(BRAINPOOL_T1, 224),
	[EC_BRAINPOOL256R1] = EC_SMW_CURVE(BRAINPOOL_R1, 256),
	[EC_BRAINPOOL256T1] = EC_SMW_CURVE(BRAINPOOL_T1, 256),
	[EC_BRAINPOOL320R1] = EC_SMW_CURVE(BRAINPOOL_R1, 320),
	[EC_BRAINPOOL320T1] = EC_SMW_CURVE(BRAINPOOL_T1, 320),
	[EC_BRAINPOOL384R1] = EC_SMW_CURVE(BRAINPOOL_R1, 384),
	[EC_BRAINPOOL384T1] = EC_SMW_CURVE(BRAINPOOL_T1, 384),
	[EC_BRAINPOOL512R1] = EC_SMW_CURVE(BRAINPOOL_R1, 512),
	[EC_BRAINPOOL512T1] = EC_SMW_CURVE(BRAINPOOL_T1, 512),
	[EC_ED25519] = EC_SMW_CURVE(ED25519, 255),
	[EC_ED448] = EC_SMW_CURVE(ED448, 448),
	[EC_NB_KEY_NAME] = { 0 }
};

/*
 * Definition of the ASN1 EC Curves supported
 */
#define CKK_UNKNOWN_KEY_TYPE CK_UNAVAILABLE_INFORMATION

#define EC_CURVE(_key_name, _ck_type)                                          \
	{                                                                      \
		.asn1 = &ec_asn1_curves[EC_##_key_name],                       \
		.dev = &ec_smw_curves[EC_##_key_name],                         \
		.ck_key_type = CKK_##_ck_type                                  \
	}

const struct curve_def ec_curves[] = {
	EC_CURVE(PRIME192V1, EC),     EC_CURVE(PRIME256V1, EC),
	EC_CURVE(SECP224R1, EC),      EC_CURVE(SECP384R1, EC),
	EC_CURVE(SECP521R1, EC),      EC_CURVE(BRAINPOOL160R1, EC),
	EC_CURVE(BRAINPOOL160T1, EC), EC_CURVE(BRAINPOOL192R1, EC),
	EC_CURVE(BRAINPOOL192T1, EC), EC_CURVE(BRAINPOOL224R1, EC),
	EC_CURVE(BRAINPOOL224T1, EC), EC_CURVE(BRAINPOOL256R1, EC),
	EC_CURVE(BRAINPOOL256T1, EC), EC_CURVE(BRAINPOOL320R1, EC),
	EC_CURVE(BRAINPOOL320T1, EC), EC_CURVE(BRAINPOOL384R1, EC),
	EC_CURVE(BRAINPOOL384T1, EC), EC_CURVE(BRAINPOOL512R1, EC),
	EC_CURVE(BRAINPOOL512T1, EC), EC_CURVE(ED25519, EC_EDWARDS),
	EC_CURVE(ED448, EC_EDWARDS),  EC_CURVE(NB_KEY_NAME, UNKNOWN_KEY_TYPE),
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
				  HKDF(CKK_GENERIC_SECRET, HKDF_IKM),
				  HKDF(CKK_HKDF, HKDF_IKM),
				  { .smw_name = SMW_KEY_TYPE_NAME_NONE } };

static CK_RV get_cipher_type_from_smw(CK_KEY_TYPE *ck_key_type,
				      smw_key_type_t key_type_name)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;
	const struct cipher_def *cipher = ciphers;

	while (cipher->smw_name != SMW_KEY_TYPE_NAME_NONE) {
		if (key_type_name == cipher->smw_name) {
			*ck_key_type = cipher->ck_key_type;
			ret = CKR_OK;
			break;
		}

		cipher++;
	};

	return ret;
}

static CK_RV get_cipher_type_from_pkcs(smw_key_type_t *key_type_name,
				       CK_KEY_TYPE ck_key_type)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;
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

static CK_RV get_hmac_type_from_smw(CK_KEY_TYPE *ck_key_type,
				    struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	const struct hmac_def *hmac = hmacs;
	smw_attr_algo_t hash_id = SMW_ATTR_HASH_NONE;

	hash_id = SMW_ATTR_GET_HASH(desc->attributes.permitted_algo);

	while (hmac->smw_name != SMW_KEY_TYPE_NAME_NONE) {
		if (desc->type_name == hmac->smw_name &&
		    hash_id == hmac->hash_id) {
			*ck_key_type = hmac->ck_key_type;
			ret = CKR_OK;
			break;
		}

		hmac++;
	};

	return ret;
}

static CK_RV get_hmac_type_from_pkcs(smw_key_type_t *key_type_name,
				     CK_KEY_TYPE ck_key_type)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;
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

static CK_RV get_ec_curve_from_smw(struct libbytes *ec_params,
				   smw_key_type_t key_type_name,
				   unsigned int security_size,
				   CK_KEY_TYPE *ck_key_type)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	const struct curve_def *curve = ec_curves;

	while (curve->dev->name) {
		if (key_type_name == curve->dev->name &&
		    security_size == curve->dev->security_size)
			break;

		curve++;
	}

	if (curve->dev->name) {
		/* Convert the curve to EC params */
		ret = util_asn1_curve_to_ec_params(curve, ec_params);
		*ck_key_type = curve->ck_key_type;
	}

	return ret;
}

static CK_RV get_ec_curve_from_pkcs(struct smw_key_descriptor *desc,
				    struct libbytes *ec_params)
{
	CK_RV ret = CKR_OK;
	const struct curve_def *curve = NULL;

	/* Verify that curve is supported */
	ret = util_asn1_ec_params_to_curve(&curve, ec_params, ec_curves);
	if (ret == CKR_OK) {
		desc->type_name = curve->dev->name;
		desc->security_size = curve->dev->security_size;
	}

	return ret;
}

static CK_RV get_rsa_type_from_smw(CK_KEY_TYPE *ck_key_type,
				   smw_key_type_t key_type_name)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	if (key_type_name == SMW_KEY_TYPE_NAME_RSA) {
		*ck_key_type = CKK_RSA;
		ret = CKR_OK;
	}

	return ret;
}

static CK_RV get_rsa_type_from_pkcs(struct smw_key_descriptor *desc)
{
	desc->type_name = SMW_KEY_TYPE_NAME_RSA;

	return CKR_OK;
}

static CK_RV ec_key_smw_to_pkcs11(unsigned int op, CK_KEY_TYPE *ck_key_type,
				  struct libobj_obj *obj,
				  struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct libobj_key_ec_pair *key = NULL;
	struct libbytes params = { 0 };

	/*
	 * Check if the SMW key type is an ECC key type, don't overwrite
	 * the @obj key type because @obj key structure allocated may not
	 * an EC key.
	 */
	if (op & OP_KEY_DESC_GET_KEY_TYPE)
		ret = get_ec_curve_from_smw(&params, desc->type_name,
					    desc->security_size, ck_key_type);

	if (ret == CKR_OK && (op & OP_KEY_DESC_GET_SECURITY_SIZE)) {
		/* Convert the curve to EC params */
		if (obj) {
			key = get_subkey_from(obj);
			key->params.number = params.number;
			key->params.array = calloc(1, params.number);
			if (key->params.array) {
				memcpy(key->params.array, params.array,
				       params.number);
				ret = CKR_OK;
			} else {
				ret = CKR_HOST_MEMORY;
			}
		} else {
			ret = CKR_FUNCTION_FAILED;
		}
	}

	if (params.array)
		free(params.array);

	return ret;
}

static CK_RV ec_key_set_buffer_from_obj(struct smw_key_descriptor *desc,
					struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_ec_pair *key = NULL;
	unsigned char *public_data = NULL;
	size_t public_length = 0;

	/*
	 * If SMW key's descriptor buffer field is set, setup it
	 * with the EC key object's buffer
	 */
	if (!desc->buffer)
		goto end;

	if (!obj) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	key = get_subkey_from(obj);
	smw_key = &desc->buffer->gen;

	if (key->point_q.array) {
		ret = util_asn1_get_field_octet_string(key->point_q.array,
						       key->point_q.number,
						       &public_data,
						       &public_length);
		if (ret != CKR_OK)
			goto end;

		/*
		 * Remove the DER ANSI X9.62 uncompress code byte
		 */
		smw_key->public_data = public_data + 1;
		if (SUB_OVERFLOW(public_length, 1, &smw_key->public_length)) {
			ret = CKR_ARGUMENTS_BAD;
			goto end;
		}
	}

	smw_key->private_data = key->value_d.value;

	if (SET_OVERFLOW(key->value_d.length, smw_key->private_length))
		ret = CKR_ARGUMENTS_BAD;
	else
		ret = CKR_OK;

end:
	return ret;
}

static CK_RV edwards_key_set_buffer_from_obj(struct smw_key_descriptor *desc,
					     struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_ec_pair *key = NULL;

	/*
	 * If SMW key's descriptor buffer field is set, setup it
	 * with the EC key object's buffer
	 */
	if (!desc->buffer)
		goto end;

	if (!obj) {
		ret = CKR_FUNCTION_FAILED;
		goto end;
	}

	key = get_subkey_from(obj);
	smw_key = &desc->buffer->gen;

	if (key->point_q.array) {
		smw_key->public_data = key->point_q.array;
		if (SET_OVERFLOW(key->point_q.number, smw_key->public_length)) {
			ret = CKR_ARGUMENTS_BAD;
			goto end;
		}
	}

	smw_key->private_data = key->value_d.value;

	if (SET_OVERFLOW(key->value_d.length, smw_key->private_length))
		ret = CKR_ARGUMENTS_BAD;
	else
		ret = CKR_OK;

end:
	return ret;
}

static CK_RV ec_key_pkcs11_to_smw(unsigned int op,
				  struct smw_key_descriptor *desc,
				  struct libbytes *ec_params,
				  struct libobj_obj *obj)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct libobj_key_ec_pair *key = NULL;
	struct libbytes *params = ec_params;

	if (op & OP_KEY_DESC_SET_KEY_TYPE ||
	    op & OP_KEY_DESC_SET_SECURITY_SIZE) {
		if (obj) {
			key = get_subkey_from(obj);
			params = &key->params;
		}

		if (!params)
			goto end;

		ret = get_ec_curve_from_pkcs(desc, params);
		if (ret != CKR_OK)
			goto end;
	}

	if (op & OP_KEY_DESC_SET_BUFFER) {
		if (!obj)
			goto end;

		switch (get_key_type(obj)) {
		case CKK_EC:
			ret = ec_key_set_buffer_from_obj(desc, obj);
			break;

		case CKK_EC_EDWARDS:
			ret = edwards_key_set_buffer_from_obj(desc, obj);
			break;

		default:
			ret = CKR_KEY_TYPE_INCONSISTENT;
			break;
		}
	}

end:
	return ret;
}

static CK_RV cipher_key_smw_to_pkcs11(unsigned int op, CK_KEY_TYPE *ck_key_type,
				      struct libobj_obj *obj,
				      struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct libobj_key_cipher *key = NULL;

	/*
	 * Check if the SMW key type is a cipher key type, don't overwrite
	 * the @obj key type because @obj key structure allocated may not
	 * a symmetric key.
	 */
	if (op & OP_KEY_DESC_GET_KEY_TYPE)
		ret = get_cipher_type_from_smw(ck_key_type, desc->type_name);

	if (ret == CKR_OK && (op & OP_KEY_DESC_GET_SECURITY_SIZE)) {
		if (obj) {
			key = get_subkey_from(obj);
			key->value_len = desc->security_size / 8;
			ret = CKR_OK;
		} else {
			ret = CKR_FUNCTION_FAILED;
		}
	}

	return ret;
}

static CK_RV cipher_key_pkcs11_to_smw(unsigned int op,
				      struct smw_key_descriptor *desc,
				      CK_KEY_TYPE key_type,
				      struct libobj_obj *obj)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_cipher *key = NULL;
	size_t key_length = 0;

	if (op & OP_KEY_DESC_SET_KEY_TYPE) {
		ret = get_cipher_type_from_pkcs(&desc->type_name, key_type);
		if (ret != CKR_OK)
			goto end;
	}

	if (op & OP_KEY_DESC_SET_SECURITY_SIZE) {
		if (!obj) {
			ret = CKR_FUNCTION_FAILED;
			goto end;
		}

		key = get_subkey_from(obj);
		key_length = key->value_len;

		switch (key_type) {
		case CKK_DES:
			desc->security_size = 56;
			break;

		case CKK_DES3:
			desc->security_size = 168;
			break;

		case CKK_AES:
			if (key_length != 16 && key_length != 24 &&
			    key_length != 32) {
				ret = CKR_ATTRIBUTE_VALUE_INVALID;
				break;
			}

			if (MUL_OVERFLOW(key_length, 8, &desc->security_size))
				ret = CKR_ATTRIBUTE_VALUE_INVALID;

			break;

		case CKK_SM4:
			if (key_length != 16)
				ret = CKR_ATTRIBUTE_VALUE_INVALID;
			else if (MUL_OVERFLOW(key_length, 8,
					      &desc->security_size))
				ret = CKR_ARGUMENTS_BAD;
			break;

		default:
			/* This case should never occurred, but ... */
			ret = CKR_GENERAL_ERROR;
		}

		if (ret != CKR_OK)
			goto end;
	}

	if (op & OP_KEY_DESC_SET_BUFFER) {
		/*
		 * If SMW key's descriptor buffer field is set, setup it
		 * with the Cipher key object's buffer
		 */
		if (desc->buffer) {
			if (!obj) {
				ret = CKR_FUNCTION_FAILED;
				goto end;
			}

			key = get_subkey_from(obj);
			smw_key = &desc->buffer->gen;
			smw_key->private_data = key->value.array;
			if (SET_OVERFLOW(key->value.number,
					 smw_key->private_length))
				ret = CKR_ARGUMENTS_BAD;
		}
	}

end:
	return ret;
}

static CK_RV hmac_key_smw_to_pkcs11(unsigned int op, CK_KEY_TYPE *ck_key_type,
				    struct libobj_obj *obj,
				    struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct libobj_key_hmac *key = NULL;

	/*
	 * Check if the SMW key type is a HMAC key type, don't overwrite
	 * the @obj key type because @obj key structure allocated may not
	 * a symmetric key.
	 */
	if (op & OP_KEY_DESC_GET_KEY_TYPE)
		ret = get_hmac_type_from_smw(ck_key_type, desc);

	if (ret == CKR_OK && (op & OP_KEY_DESC_GET_SECURITY_SIZE)) {
		if (obj) {
			key = get_subkey_from(obj);
			key->value_len = desc->security_size / 8;
			ret = CKR_OK;
		} else {
			ret = CKR_FUNCTION_FAILED;
		}
	}

	return ret;
}

static CK_RV hmac_key_pkcs11_to_smw(unsigned int op,
				    struct smw_key_descriptor *desc,
				    CK_KEY_TYPE key_type,
				    struct libobj_obj *obj)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct smw_keypair_gen *smw_key = NULL;
	struct libobj_key_hmac *key = NULL;
	size_t key_length = 0;

	if (op & OP_KEY_DESC_SET_KEY_TYPE) {
		ret = get_hmac_type_from_pkcs(&desc->type_name, key_type);
		if (ret != CKR_OK)
			goto end;
	}

	if (op & OP_KEY_DESC_SET_SECURITY_SIZE) {
		if (!obj) {
			ret = CKR_FUNCTION_FAILED;
			goto end;
		}

		key = get_subkey_from(obj);
		key_length = key->value_len;

		if (MUL_OVERFLOW(key_length, 8, &desc->security_size)) {
			ret = CKR_ARGUMENTS_BAD;
			goto end;
		}
	}

	if (op & OP_KEY_DESC_SET_BUFFER) {
		/*
		 * If SMW key's descriptor buffer field is set, setup it
		 * with the Cipher key object's buffer
		 */
		if (desc->buffer) {
			if (!obj) {
				ret = CKR_FUNCTION_FAILED;
				goto end;
			}

			key = get_subkey_from(obj);
			smw_key = &desc->buffer->gen;
			smw_key->private_data = key->value.array;
			if (SET_OVERFLOW(key->value.number,
					 smw_key->private_length))
				ret = CKR_ARGUMENTS_BAD;
		}
	}

end:
	return ret;
}

static CK_RV rsa_key_smw_to_pkcs11(unsigned int op, CK_KEY_TYPE *ck_key_type,
				   struct libobj_obj *obj,
				   struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct libobj_key_rsa_pair *key = NULL;

	/*
	 * Check if the SMW key type is a RSA key type, don't overwrite
	 * the @obj key type because @obj key structure allocated may not
	 * a RSA key.
	 */
	if (op & OP_KEY_DESC_GET_KEY_TYPE)
		ret = get_rsa_type_from_smw(ck_key_type, desc->type_name);

	if (ret == CKR_OK && (op & OP_KEY_DESC_GET_SECURITY_SIZE)) {
		/*
		 * Modulus length defines the RSA security size
		 */
		if (obj) {
			key = get_subkey_from(obj);
			key->modulus_length = desc->security_size;

			ret = CKR_OK;
		} else {
			ret = CKR_FUNCTION_FAILED;
		}
	}

	return ret;
}

static CK_RV rsa_key_pks11_to_smw(unsigned int op,
				  struct smw_key_descriptor *desc,
				  struct libobj_obj *obj)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	struct smw_keypair_rsa *smw_key = NULL;
	struct libobj_key_rsa_pair *key = NULL;
	size_t security_size = 0;

	if (op & OP_KEY_DESC_SET_KEY_TYPE) {
		ret = get_rsa_type_from_pkcs(desc);
		if (ret != CKR_OK)
			goto end;
	}

	if (op & OP_KEY_DESC_SET_SECURITY_SIZE) {
		if (!obj) {
			ret = CKR_FUNCTION_FAILED;
			goto end;
		}

		key = get_subkey_from(obj);

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
			ret = CKR_ATTRIBUTE_VALUE_INVALID;

		else if (SET_OVERFLOW(security_size, desc->security_size))
			ret = CKR_ARGUMENTS_BAD;

		if (ret != CKR_OK)
			goto end;
	}

	if (op & OP_KEY_DESC_SET_BUFFER) {
		/*
		 * If SMW key's descriptor buffer field is set, setup it
		 * with the RSA key object's buffer
		 */
		if (desc->buffer) {
			if (!obj) {
				ret = CKR_FUNCTION_FAILED;
				goto end;
			}

			key = get_subkey_from(obj);
			smw_key = &desc->buffer->rsa;
			smw_key->modulus = key->modulus.value;

			if (SET_OVERFLOW(key->modulus.length,
					 smw_key->modulus_length)) {
				ret = CKR_ARGUMENTS_BAD;
				goto end;
			}

			smw_key->public_data = key->pub_exp.value;
			if (SET_OVERFLOW(key->pub_exp.length,
					 smw_key->public_length)) {
				ret = CKR_ARGUMENTS_BAD;
				goto end;
			}

			smw_key->private_data = key->priv_exp.value;
			if (SET_OVERFLOW(key->priv_exp.length,
					 smw_key->private_length)) {
				ret = CKR_ARGUMENTS_BAD;
				goto end;
			}

			smw_key->public_exponent = key->pub_exp.value;
			if (SET_OVERFLOW(key->pub_exp.length,
					 smw_key->public_exponent_length)) {
				ret = CKR_ARGUMENTS_BAD;
				goto end;
			}
		}
	}

end:
	return ret;
}

static CK_RV op_key_desc_setup(unsigned int op, struct smw_key_descriptor *desc,
			       CK_KEY_TYPE key_type, struct libbytes *ec_params,
			       struct libobj_obj *obj)
{
	CK_RV ret = CKR_KEY_TYPE_INCONSISTENT;

	CK_KEY_TYPE tmp_key_type = 0;

	switch (key_type) {
	case CKK_AES:
	case CKK_DES:
	case CKK_DES3:
	case CKK_SM4:
		if (op & OP_KEY_DESC_GET_ALL)
			ret = cipher_key_smw_to_pkcs11(op, &tmp_key_type, obj,
						       desc);
		else
			ret = cipher_key_pkcs11_to_smw(op, desc, key_type, obj);

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
	case CKK_GENERIC_SECRET:
	case CKK_HKDF:
		if (op & OP_KEY_DESC_GET_ALL)
			ret = hmac_key_smw_to_pkcs11(op, &tmp_key_type, obj,
						     desc);
		else
			ret = hmac_key_pkcs11_to_smw(op, desc, key_type, obj);

		break;

	case CKK_EC:
	case CKK_EC_EDWARDS:
		if (op & OP_KEY_DESC_GET_ALL)
			ret = ec_key_smw_to_pkcs11(op, &tmp_key_type, obj,
						   desc);
		else
			ret = ec_key_pkcs11_to_smw(op, desc, ec_params, obj);

		break;

	case CKK_RSA:
		if (op & OP_KEY_DESC_GET_ALL)
			ret = rsa_key_smw_to_pkcs11(op, &tmp_key_type, obj,
						    desc);
		else
			ret = rsa_key_pks11_to_smw(op, desc, obj);

		break;

	default:
		break;
	}

	return ret;
}

CK_RV key_desc_smw_to_pkcs11(struct libobj_obj *obj,
			     struct smw_get_key_attributes_args *attributes)
{
	struct smw_key_descriptor *desc = attributes->key_descriptor;

	return op_key_desc_setup(OP_KEY_DESC_GET_ALL, desc, get_key_type(obj),
				 NULL, obj);
}

CK_RV key_desc_setup(struct smw_key_descriptor *desc, struct libobj_obj *obj)
{
	return op_key_desc_setup(OP_KEY_DESC_SET_ALL, desc, get_key_type(obj),
				 NULL, obj);
}

CK_RV key_desc_set_key_type(struct smw_key_descriptor *desc,
			    CK_KEY_TYPE key_type, struct libbytes *ec_params)
{
	return op_key_desc_setup(OP_KEY_DESC_SET_KEY_TYPE, desc, key_type,
				 ec_params, NULL);
}

CK_RV key_desc_get_key_type(CK_KEY_TYPE *key_type,
			    struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_OK;

	ret = cipher_key_smw_to_pkcs11(OP_KEY_DESC_GET_KEY_TYPE, key_type, NULL,
				       desc);
	if (ret == CKR_OK)
		goto end;

	ret = hmac_key_smw_to_pkcs11(OP_KEY_DESC_GET_KEY_TYPE, key_type, NULL,
				     desc);
	if (ret == CKR_OK)
		goto end;

	ret = rsa_key_smw_to_pkcs11(OP_KEY_DESC_GET_KEY_TYPE, key_type, NULL,
				    desc);
	if (ret == CKR_OK)
		goto end;

	ret = ec_key_smw_to_pkcs11(OP_KEY_DESC_GET_KEY_TYPE, key_type, NULL,
				   desc);

end:
	return ret;
}

CK_BBOOL is_edwards_key_type(struct libobj_obj *obj, smw_key_type_t key_type)
{
	CK_RV ret = CKR_OK;

	struct smw_key_descriptor desc = { 0 };

	ret = ec_key_pkcs11_to_smw(OP_KEY_DESC_SET_KEY_TYPE, &desc, NULL, obj);

	if (ret != CKR_OK)
		return CK_FALSE;

	return (desc.type_name == key_type) ? CK_TRUE : CK_FALSE;
}

int base_key_desc_setup(struct libobj_obj *obj, struct smw_key_descriptor *desc)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;

	struct libobj_key_cipher *cipher_key = NULL;
	struct libobj_key_hmac *hmac_key = NULL;
	struct libbytes *key_value = NULL;
	CK_KEY_TYPE key_type = get_key_type(obj);
	struct smw_keypair_gen *smw_key = NULL;

	desc->id = get_key_token_id(obj);
	if (desc->id) {
		ret = CKR_OK;
	} else if (desc->buffer) {
		desc->type_name = SMW_KEY_TYPE_NAME_RAW;

		switch (key_type) {
		case CKK_AES:
		case CKK_DES:
		case CKK_DES3:
		case CKK_SM4:
			cipher_key = get_subkey_from(obj);
			key_value = &cipher_key->value;
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
		case CKK_GENERIC_SECRET:
		case CKK_HKDF:
			hmac_key = get_subkey_from(obj);
			key_value = &hmac_key->value;
			break;

		case CKK_EC:
			ret = key_desc_setup(desc, obj);
			break;

		default:
			break;
		}

		if (key_value) {
			smw_key = &desc->buffer->gen;
			smw_key->public_data = key_value->array;
			if (!SET_OVERFLOW(key_value->number,
					  smw_key->public_length))
				ret = CKR_OK;
		}
	}

	return ret;
}

CK_RV derived_key_desc_setup(struct smw_derived_key_descriptor *desc,
			     struct libobj_obj *obj)
{
	int ret = CKR_OK;
	struct smw_key_descriptor tmp_desc = { 0 };

	ret = op_key_desc_setup(OP_KEY_DESC_SET_KEY_TYPE |
					OP_KEY_DESC_SET_SECURITY_SIZE,
				&tmp_desc, get_key_type(obj), NULL, obj);
	if (ret == CKR_OK) {
		desc->security_size = tmp_desc.security_size;
		desc->type_name = tmp_desc.type_name;
	}

	return ret;
}
