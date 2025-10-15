// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include <inttypes.h>

#include "smw_keymgr.h"
#include "smw_crypto.h"

#include "psa/crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"

#include "asn1.h"
#include "common.h"
#include "util_status.h"

#define KEY_TYPE(_smw, _psa)                                                   \
	{                                                                      \
		.smw_key_type = SMW_KEY_TYPE_NAME_##_smw,                      \
		.smw_algo = SMW_ATTR_ALGO_##_smw,                              \
		.psa_key_type = PSA_KEY_TYPE_##_psa,                           \
	}

#define KEY_TYPE_GENERAL(_smw, _algo, _psa)                                    \
	{                                                                      \
		.smw_key_type = SMW_KEY_TYPE_NAME_##_smw,                      \
		.smw_algo = SMW_ATTR_ALGO_##_algo,                             \
		.psa_key_type = PSA_KEY_TYPE_##_psa,                           \
	}

/**
 * struct - Cipher key type
 * @smw_key_type: SMW key type name.
 * @smw_algo: SMW main algorithm based on key name.
 * @psa_key_type: PSA key type.
 */
static const struct cipher_key_type {
	smw_key_type_t smw_key_type;
	smw_attr_algo_t smw_algo;
	psa_key_type_t psa_key_type;
} cipher_key_type[] = {
	KEY_TYPE(AES, AES),
	KEY_TYPE(DES, DES),
	KEY_TYPE(DES3, DES),
	KEY_TYPE(SM4, SM4),
};

static const struct {
	smw_key_type_t smw_key_type;
	smw_attr_algo_t smw_algo;
	psa_key_type_t psa_key_type;
} general_key_type[] = {
	KEY_TYPE_GENERAL(DERIVE, NONE, DERIVE),
	KEY_TYPE_GENERAL(DERIVE, TLS_1_2, DERIVE),
	KEY_TYPE_GENERAL(DERIVE, TLS_1_3, DERIVE),
};

#define ECC_KEY_TYPE(_smw, _family, _fixed_size)                               \
	{                                                                      \
		.smw_key_type = SMW_KEY_TYPE_NAME_##_smw,                      \
		.ecc_family = PSA_ECC_FAMILY_##_family,                        \
		.fixed_size = _fixed_size                                      \
	}

/**
 * struct - ECC key type
 * @smw_key_type: SMW HMAC key type name.
 * @ecc_family: Elliptic curve family.
 */
struct ecc_key_type {
	smw_key_type_t smw_key_type;
	psa_ecc_family_t ecc_family;
	size_t fixed_size;
};

static const struct ecc_key_type ecc_key_type[] = {
	ECC_KEY_TYPE(SECP_R1, SECP_R1, 0),
	ECC_KEY_TYPE(BRAINPOOL_R1, BRAINPOOL_P_R1, 0),
	ECC_KEY_TYPE(ED25519, TWISTED_EDWARDS, 255),
	ECC_KEY_TYPE(ED448, TWISTED_EDWARDS, 448),
	ECC_KEY_TYPE(X25519, MONTGOMERY, 255),
	ECC_KEY_TYPE(X448, MONTGOMERY, 448),
};

#define KEY_USAGE(_name)                                                       \
	{                                                                      \
		.smw_usage = SMW_ATTR_USAGE_##_name,                           \
		.psa_usage = PSA_KEY_USAGE_##_name,                            \
	}

/**
 * struct - Key usage
 * @smw_usage: SMW usage.
 * @psa_usage_flags: PSA usage flags.
 */
static const struct {
	smw_attr_usage_t smw_usage;
	psa_key_usage_t psa_usage;
} key_usage[] = { KEY_USAGE(EXPORT),	   KEY_USAGE(COPY),
		  KEY_USAGE(ENCRYPT),	   KEY_USAGE(DECRYPT),
		  KEY_USAGE(SIGN_MESSAGE), KEY_USAGE(VERIFY_MESSAGE),
		  KEY_USAGE(SIGN_HASH),	   KEY_USAGE(VERIFY_HASH),
		  KEY_USAGE(DERIVE) };

#define KEY_ALGORITHM(_psa_alg, _smw_algo, _smw_mode, _smw_class)              \
	{                                                                      \
		.psa_alg = PSA_ALG_##_psa_alg,                                 \
		.smw_algo = SMW_ATTR_ALGO_##_smw_algo,                         \
		.smw_mode = SMW_ATTR_MODE_##_smw_mode,                         \
		.smw_class = SMW_ATTR_CLASS_##_smw_class,                      \
	}

#define KEY_ALGORITHM_CURVE(_psa_alg, _smw_algo, _smw_curve, _smw_class)       \
	{                                                                      \
		.psa_alg = PSA_ALG_##_psa_alg,                                 \
		.smw_algo = SMW_ATTR_ALGO_##_smw_algo,                         \
		.smw_curve = SMW_ATTR_CURVE_##_smw_curve,                      \
		.smw_class = SMW_ATTR_CLASS_##_smw_class,                      \
	}

#define KEY_HASH(_smw, _psa)                                                   \
	{                                                                      \
		.smw_hash = SMW_ATTR_HASH_##_smw, .psa_hash = PSA_ALG_##_psa   \
	}

/**
 * struct - Key hash
 * @smw_hash: SMW hash algo ID.
 * @psa_hash: PSA hash id.
 */
static const struct {
	smw_attr_algo_t smw_hash;
	psa_algorithm_t psa_hash;
} key_hash[] = { KEY_HASH(MD5, MD5),	       KEY_HASH(SHA1, SHA_1),
		 KEY_HASH(SHA224, SHA_224),    KEY_HASH(SHA256, SHA_256),
		 KEY_HASH(SHA384, SHA_384),    KEY_HASH(SHA512, SHA_512),
		 KEY_HASH(SHA3_224, SHA3_224), KEY_HASH(SHA3_256, SHA3_256),
		 KEY_HASH(SHA3_384, SHA3_384), KEY_HASH(SHA3_512, SHA3_512),
		 KEY_HASH(SM3, SM3),	       KEY_HASH(ANY, ANY_HASH) };

#define KEY_CIPHER(_smw, _psa)                                                 \
	{                                                                      \
		.smw_cipher = SMW_ATTR_MODE_##_smw,                            \
		.psa_cipher = PSA_ALG_##_psa                                   \
	}

/**
 * struct - Cipher Mode
 * @smw_cipher: SMW cipher algo ID.
 * @psa_cipher: PSA cipher id.
 */
static const struct {
	smw_attr_algo_t smw_cipher;
	psa_algorithm_t psa_cipher;
} cipher_mode[] = { KEY_CIPHER(ECB_NO_PAD, ECB_NO_PADDING),
		    KEY_CIPHER(CBC_NO_PAD, CBC_NO_PADDING),
		    KEY_CIPHER(CFB, CFB),
		    KEY_CIPHER(CTR, CTR),
		    KEY_CIPHER(OFB, OFB),
		    KEY_CIPHER(XTS, XTS) };

#define KEY_PERSISTENCE(_smw, _psa)                                            \
	{                                                                      \
		.smw_persistence = SMW_ATTR_PERSISTENCE_##_smw,                \
		.psa_persistence = PSA_KEY_PERSISTENCE_##_psa                  \
	}

/**
 * struct - Key persistence
 * @smw_persistence: SMW persistence.
 * @psa_persistence: PSA persistence.
 */
static const struct {
	smw_attr_attributes_t smw_persistence;
	psa_key_persistence_t psa_persistence;
} key_persistence[] = { KEY_PERSISTENCE(TRANSIENT, VOLATILE),
			KEY_PERSISTENCE(PERSISTENT, DEFAULT),
			KEY_PERSISTENCE(PERMANENT, READ_ONLY) };

static bool is_ecc_key_type(smw_key_type_t type_name)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!type_name)
		return false;

	if (type_name == SMW_KEY_TYPE_NAME_SECP_R1 ||
	    type_name == SMW_KEY_TYPE_NAME_BRAINPOOL_R1 ||
	    type_name == SMW_KEY_TYPE_NAME_BRAINPOOL_T1 ||
	    type_name == SMW_KEY_TYPE_NAME_ED25519 ||
	    type_name == SMW_KEY_TYPE_NAME_ED448 ||
	    type_name == SMW_KEY_TYPE_NAME_X25519 ||
	    type_name == SMW_KEY_TYPE_NAME_X448)
		return true;

	return false;
}

static psa_status_t set_rsa_key_pair_buffer(const uint8_t *data,
					    size_t data_length,
					    struct smw_keypair_rsa *keypair_rsa)
{
	struct asn1_integer sequence[9] = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_length || !keypair_rsa)
		return PSA_ERROR_INVALID_ARGUMENT;

	/*
	 *	RSAPrivateKey ::= SEQUENCE {
	 *	    version             INTEGER,  -- must be 0
	 *	    modulus             INTEGER,  -- n
	 *	    publicExponent      INTEGER,  -- e
	 *	    privateExponent     INTEGER,  -- d
	 *	    prime1              INTEGER,  -- p
	 *	    prime2              INTEGER,  -- q
	 *	    exponent1           INTEGER,  -- d mod (p-1)
	 *	    exponent2           INTEGER,  -- d mod (q-1)
	 *	    coefficient         INTEGER,  -- (inverse of q) mod p
	 *	}
	 */

	if (asn1_decode_sequence_integer(data, data_length, sequence,
					 ARRAY_SIZE(sequence)))
		return PSA_ERROR_INVALID_ARGUMENT;

	/* Check version is 0 */
	if (sequence[0].length != 1 || !sequence[0].value || *sequence[0].value)
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_rsa->modulus = sequence[1].value;

	if (SET_OVERFLOW(sequence[1].length, keypair_rsa->modulus_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_rsa->public_data = sequence[2].value;

	if (SET_OVERFLOW(sequence[2].length, keypair_rsa->public_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_rsa->private_data = sequence[3].value;

	if (SET_OVERFLOW(sequence[3].length, keypair_rsa->private_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	return PSA_SUCCESS;
}

static psa_status_t
set_rsa_public_key_buffer(const uint8_t *data, size_t data_length,
			  struct smw_keypair_rsa *keypair_rsa)
{
	struct asn1_integer sequence[2] = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_length || !keypair_rsa)
		return PSA_ERROR_INVALID_ARGUMENT;

	/*
	 *	RSAPublicKey ::= SEQUENCE {
	 *	   modulus            INTEGER,    -- n
	 *	   publicExponent     INTEGER  }  -- e
	 */

	if (asn1_decode_sequence_integer(data, data_length, sequence,
					 ARRAY_SIZE(sequence)))
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_rsa->modulus = sequence[0].value;

	if (SET_OVERFLOW(sequence[0].length, keypair_rsa->modulus_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_rsa->public_data = sequence[1].value;

	if (SET_OVERFLOW(sequence[1].length, keypair_rsa->public_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	return PSA_SUCCESS;
}

static psa_status_t set_rsa_key_buffer(psa_key_type_t key_type,
				       const uint8_t *data, size_t data_length,
				       struct smw_keypair_rsa *keypair_rsa)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_length || !keypair_rsa)
		return psa_status;

	if (!PSA_KEY_TYPE_IS_RSA(key_type))
		return psa_status;

	if (PSA_KEY_TYPE_IS_KEY_PAIR(key_type)) {
		psa_status =
			set_rsa_key_pair_buffer(data, data_length, keypair_rsa);
	} else if (PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type)) {
		psa_status = set_rsa_public_key_buffer(data, data_length,
						       keypair_rsa);
	} else {
		psa_status = PSA_ERROR_NOT_SUPPORTED;
	}

	return psa_status;
}

static void set_gen_private_key_buffer(const uint8_t *data, size_t data_length,
				       struct smw_keypair_gen *keypair_gen)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	keypair_gen->private_data = (unsigned char *)data;
	(void)SET_OVERFLOW(data_length, keypair_gen->private_length);
}

static void set_ecc_public_key_buffer(const uint8_t *data, size_t data_length,
				      struct smw_keypair_gen *keypair_gen)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Remove byte 0x04 */
	keypair_gen->public_data = (unsigned char *)data + 1;
	(void)SET_OVERFLOW(data_length - 1, keypair_gen->public_length);
}

static void set_ecc_key_buffer(psa_key_type_t key_type, const uint8_t *data,
			       size_t data_length,
			       struct smw_keypair_gen *keypair_gen)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type))
		set_ecc_public_key_buffer(data, data_length, keypair_gen);
	else
		set_gen_private_key_buffer(data, data_length, keypair_gen);
}

static smw_key_type_t get_ecc_smw_key_type(psa_ecc_family_t ecc_family,
					   unsigned int security_size)
{
	smw_key_type_t key_type = SMW_KEY_TYPE_NAME_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(ecc_key_type); i++) {
		if (ecc_key_type[i].ecc_family != ecc_family)
			continue;

		if (ecc_key_type[i].fixed_size &&
		    ecc_key_type[i].fixed_size != security_size)
			continue;

		key_type = ecc_key_type[i].smw_key_type;
		break;
	}

	return key_type;
}

static psa_key_type_t get_ecc_psa_key_type(smw_key_type_t smw_key_type,
					   bool is_keypair)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	psa_ecc_family_t ecc_family = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; !ecc_family && i < ARRAY_SIZE(ecc_key_type); i++) {
		if (ecc_key_type[i].smw_key_type == smw_key_type)
			ecc_family = ecc_key_type[i].ecc_family;
	}

	if (!ecc_family)
		return psa_key_type;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family);
	else
		psa_key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(ecc_family);

	return psa_key_type;
}

static psa_key_type_t get_dh_psa_key_type(smw_key_type_t smw_key_type,
					  bool is_keypair)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;

	if (smw_key_type != SMW_KEY_TYPE_NAME_DH)
		return psa_key_type;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
	else
		psa_key_type =
			PSA_KEY_TYPE_DH_PUBLIC_KEY(PSA_DH_FAMILY_RFC7919);

	return psa_key_type;
}

static psa_key_type_t get_rsa_psa_key_type(smw_key_type_t smw_key_type,
					   bool is_keypair)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;

	if (smw_key_type != SMW_KEY_TYPE_NAME_RSA)
		return psa_key_type;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_RSA_KEY_PAIR;
	else
		psa_key_type = PSA_KEY_TYPE_RSA_PUBLIC_KEY;

	return psa_key_type;
}

static psa_key_type_t get_hmac_psa_key_type(smw_key_type_t smw_key_type)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;

	if (smw_key_type == SMW_KEY_TYPE_NAME_HMAC)
		psa_key_type = PSA_KEY_TYPE_HMAC;

	return psa_key_type;
}

psa_key_type_t get_cipher_psa_key_type(smw_key_type_t smw_key_type)
{
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (cipher_key_type[i].smw_key_type == smw_key_type) {
			SMW_DBG_PRINTF(DEBUG, "Key type name: %d\n",
				       cipher_key_type[i].smw_key_type);
			return cipher_key_type[i].psa_key_type;
		}
	}

	return PSA_KEY_TYPE_NONE;
}

psa_key_type_t get_general_psa_key_type(smw_key_type_t smw_key_type)
{
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(general_key_type); i++) {
		if (general_key_type[i].smw_key_type == smw_key_type) {
			SMW_DBG_PRINTF(DEBUG, "Key type name: %d\n",
				       general_key_type[i].smw_key_type);
			return general_key_type[i].psa_key_type;
		}
	}

	return PSA_KEY_TYPE_NONE;
}

static smw_attr_algo_t get_cipher_algo_key_type(smw_key_type_t smw_key_type)
{
	smw_attr_algo_t smw_algo = SMW_ATTR_ALGO_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (cipher_key_type[i].smw_key_type == smw_key_type) {
			smw_algo = cipher_key_type[i].smw_algo;
			SMW_DBG_PRINTF(DEBUG, "SMW Cipher Algo: 0x%.8x\n",
				       smw_algo);
			break;
		}
	}

	return smw_algo;
}

static smw_key_type_t get_smw_key_type(const psa_key_attributes_t *attributes,
				       unsigned int security_size)
{
	unsigned int i = 0;

	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	psa_ecc_family_t ecc_family = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attributes)
		return SMW_KEY_TYPE_NAME_NONE;

	psa_key_type = psa_get_key_type(attributes);

	if (psa_key_type == PSA_KEY_TYPE_DG_PROVISIONING_KEY)
		return SMW_KEY_TYPE_NAME_EL2GO_PROV_OEM_KEY;

	if (psa_key_type == PSA_KEY_TYPE_RAW_DATA)
		return SMW_KEY_TYPE_NAME_RAW;

	if (psa_key_type == PSA_KEY_TYPE_DERIVE)
		return SMW_KEY_TYPE_NAME_DERIVE;

	if (PSA_KEY_TYPE_IS_DH(psa_key_type))
		return SMW_KEY_TYPE_NAME_DH;

	if (PSA_KEY_TYPE_IS_RSA(psa_key_type))
		return SMW_KEY_TYPE_NAME_RSA;

	if (psa_key_type == PSA_KEY_TYPE_DES) {
		if (security_size == 56)
			return SMW_KEY_TYPE_NAME_DES;
		else if (security_size == 112 || security_size == 168)
			return SMW_KEY_TYPE_NAME_DES3;
		else
			return SMW_KEY_TYPE_NAME_NONE;
	}

	if (psa_key_type == PSA_KEY_TYPE_HMAC)
		return SMW_KEY_TYPE_NAME_HMAC;

	if (PSA_KEY_TYPE_IS_ECC(psa_key_type)) {
		ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_key_type);

		return get_ecc_smw_key_type(ecc_family, security_size);
	}

	for (; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (cipher_key_type[i].psa_key_type == psa_key_type) {
			SMW_DBG_PRINTF(DEBUG, "Key type: %d\n",
				       cipher_key_type[i].smw_key_type);
			return cipher_key_type[i].smw_key_type;
		}
	}

	return SMW_KEY_TYPE_NAME_NONE;
}

static psa_status_t get_psa_key_type(psa_key_type_t *psa_key_type,
				     const smw_key_type_t smw_key_type,
				     smw_key_privacy_t privacy)
{
	psa_status_t status = PSA_ERROR_DATA_INVALID;
	bool is_keypair = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (privacy != SMW_KEY_PRIVACY_NAME_NONE && smw_key_type) {
		if (privacy == SMW_KEY_PRIVACY_NAME_PAIR)
			is_keypair = true;

		*psa_key_type = get_dh_psa_key_type(smw_key_type, is_keypair);
		if (*psa_key_type == PSA_KEY_TYPE_NONE)
			*psa_key_type =
				get_rsa_psa_key_type(smw_key_type, is_keypair);
		if (*psa_key_type == PSA_KEY_TYPE_NONE)
			*psa_key_type =
				get_ecc_psa_key_type(smw_key_type, is_keypair);
		if (*psa_key_type == PSA_KEY_TYPE_NONE)
			*psa_key_type = get_hmac_psa_key_type(smw_key_type);
		if (*psa_key_type == PSA_KEY_TYPE_NONE)
			*psa_key_type = get_cipher_psa_key_type(smw_key_type);
		if (*psa_key_type == PSA_KEY_TYPE_NONE)
			*psa_key_type = get_general_psa_key_type(smw_key_type);
		if (*psa_key_type != PSA_KEY_TYPE_NONE)
			status = PSA_SUCCESS;
	}

	return status;
}

static smw_attr_algo_t get_smw_hash(psa_algorithm_t psa_hash)
{
	smw_attr_algo_t smw_hash = SMW_ATTR_ALGO_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(key_hash); i++) {
		if (psa_hash == key_hash[i].psa_hash) {
			smw_hash = key_hash[i].smw_hash;
			SMW_DBG_PRINTF(DEBUG,
				       "Key hash: 0x%.8x -> 0x%" PRIx64 "\n",
				       psa_hash, smw_hash);
			break;
		}
	}

	return smw_hash;
}

static psa_algorithm_t get_psa_hash(smw_attr_algo_t smw_hash)
{
	psa_algorithm_t psa_alg = PSA_ALG_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(key_hash); i++) {
		if (smw_hash == key_hash[i].smw_hash) {
			psa_alg = key_hash[i].psa_hash;
			SMW_DBG_PRINTF(DEBUG,
				       "Key hash: 0x%" PRIx64 " -> 0x%.8x\n",
				       smw_hash, psa_alg);
			break;
		}
	}

	return psa_alg;
}

static smw_attr_algo_t get_smw_cipher_mode(psa_algorithm_t psa_alg)
{
	smw_attr_algo_t smw_mode = SMW_ATTR_MODE_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(cipher_mode); i++) {
		if (psa_alg == cipher_mode[i].psa_cipher) {
			smw_mode = cipher_mode[i].smw_cipher;
			SMW_DBG_PRINTF(DEBUG, "SMW Cipher Mode: 0x%.8x\n",
				       smw_mode);
			break;
		}
	}

	return smw_mode;
}

static psa_algorithm_t get_psa_cipher_alg(smw_attr_algo_t mode)
{
	psa_algorithm_t psa_alg = PSA_ALG_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(cipher_mode); i++) {
		if (mode == cipher_mode[i].smw_cipher) {
			psa_alg = cipher_mode[i].psa_cipher;
			SMW_DBG_PRINTF(DEBUG, "PSA Cipher Mode: 0x%.8x\n",
				       psa_alg);
			break;
		}
	}

	return psa_alg;
}

#define KDF_ALGO(_smw, _psa, _hash)                                            \
	{                                                                      \
		.smw_algo = SMW_ATTR_ALGO_##_smw,                              \
		.psa_algo = PSA_ALG_##_psa##_BASE, .with_hash = _hash          \
	}
static const struct {
	smw_attr_algo_t smw_algo;
	psa_algorithm_t psa_algo;
	bool with_hash;
} kdf_algo[] = {
	KDF_ALGO(HKDF, HKDF, true),
	KDF_ALGO(HKDF_EXTRACT, HKDF_EXTRACT, true),
	KDF_ALGO(HKDF_EXPAND, HKDF_EXPAND, true),
	KDF_ALGO(TLS_1_2, TLS12_PRF, true),
	KDF_ALGO(CKDF, VENDOR_CKDF, false),
	KDF_ALGO(TLS_1_3, VENDOR_TLS13, true),
};

static smw_attr_algo_t get_smw_kdf_algo(psa_algorithm_t psa_algo)
{
	smw_attr_algo_t smw_algo = SMW_ATTR_ALGO_NONE;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(kdf_algo); i++) {
		if (psa_algo != kdf_algo[i].psa_algo)
			continue;

		smw_algo = kdf_algo[i].smw_algo;
		break;
	}

	return smw_algo;
}

static psa_algorithm_t get_psa_kdf_algo(smw_attr_algo_t smw_algo,
					psa_algorithm_t psa_hash)
{
	psa_algorithm_t psa_algo = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(kdf_algo); i++) {
		if (smw_algo != kdf_algo[i].smw_algo)
			continue;

		psa_algo = kdf_algo[i].psa_algo;
		if (kdf_algo[i].with_hash)
			SET_BITS(psa_algo, (psa_hash & PSA_ALG_HASH_MASK));

		break;
	}

	return psa_algo;
}

static psa_key_usage_t get_psa_usage_flags(smw_attr_usage_t smw_usage_flags)
{
	psa_key_usage_t psa_usage_flags = 0;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (key_usage[i].smw_usage & smw_usage_flags)
			psa_usage_flags |= key_usage[i].psa_usage;
	}

	return psa_usage_flags;
}

static smw_attr_usage_t get_smw_usage_flags(psa_key_usage_t psa_usage_flags)
{
	smw_attr_usage_t smw_usage_flags = SMW_ATTR_USAGE_NONE;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (key_usage[i].psa_usage & psa_usage_flags)
			smw_usage_flags |= key_usage[i].smw_usage;
	}

	return smw_usage_flags;
}

static psa_status_t get_psa_persistence(psa_key_persistence_t *persistence,
					smw_attr_attributes_t attributes)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(key_persistence); i++) {
		if (key_persistence[i].smw_persistence ==
		    SMW_ATTR_GET_PERSISTENCE(attributes)) {
			*persistence = key_persistence[i].psa_persistence;
			return PSA_SUCCESS;
		}
	}

	return PSA_ERROR_DATA_INVALID;
}

static smw_attr_attributes_t get_smw_persistence(psa_key_lifetime_t lifetime)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(key_persistence); i++) {
		if (key_persistence[i].psa_persistence ==
		    PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime)) {
			return key_persistence[i].smw_persistence;
		}
	}

	return 0;
}

static void set_aead_tag_length(psa_algorithm_t *psa_alg, uint8_t length,
				bool is_min_length)
{
	if (is_min_length)
		*psa_alg = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(*psa_alg,
								      length);
	else if (length)
		*psa_alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(*psa_alg, length);
}

static void set_mac_length(psa_algorithm_t *psa_alg, uint8_t length,
			   uint8_t is_min_length)
{
	if (is_min_length)
		*psa_alg = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(*psa_alg, length);
	else if (length)
		*psa_alg = PSA_ALG_TRUNCATED_MAC(*psa_alg, length);
}

static psa_status_t get_psa_alg(psa_algorithm_t *psa_alg,
				smw_attr_algo_t permitted_algo)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
	psa_algorithm_t psa_hash = PSA_ALG_NONE;
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_attr_algo_t mode = SMW_ATTR_MODE_NONE;
	smw_attr_algo_t curve = SMW_ATTR_CURVE_NONE;
	smw_attr_algo_t hash = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t class = SMW_ATTR_CLASS_NONE;
	uint8_t length = 0;
	bool is_min_length = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*psa_alg = PSA_ALG_NONE;

	algo = SMW_ATTR_GET_ALGO(permitted_algo);
	mode = SMW_ATTR_GET_MODE(permitted_algo);
	curve = SMW_ATTR_GET_CURVE(permitted_algo);
	hash = SMW_ATTR_GET_HASH(permitted_algo);
	class = SMW_ATTR_GET_CLASS(permitted_algo);
	is_min_length = SMW_ATTR_IS_MIN_LENGTH(permitted_algo);

	if (SET_OVERFLOW(SMW_ATTR_GET_LENGTH(permitted_algo), length))
		goto end;

	psa_hash = get_psa_hash(hash);

	switch (class) {
	case SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION:
		if (algo == SMW_ATTR_ALGO_AES || algo == SMW_ATTR_ALGO_DES ||
		    algo == SMW_ATTR_ALGO_DES3 ||
		    algo == SMW_ATTR_ALGO_CHACHA20 || algo == SMW_ATTR_ALGO_SM4)
			*psa_alg = get_psa_cipher_alg(mode);
		break;

	case SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION:
		if (algo == SMW_ATTR_ALGO_RSA) {
			if (mode == SMW_ATTR_MODE_PKCS1_1_5)
				*psa_alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
			else if (mode == SMW_ATTR_MODE_OAEP)
				*psa_alg = PSA_ALG_RSA_OAEP(psa_hash);
		}
		break;

	case SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE:
		if (algo == SMW_ATTR_ALGO_ECDSA) {
			*psa_alg = PSA_ALG_ECDSA(psa_hash);
		} else if (algo == SMW_ATTR_ALGO_EDDSA) {
			switch (curve) {
			case SMW_ATTR_CURVE_ED25519:
				*psa_alg = PSA_ALG_ED25519PH;
				break;
			case SMW_ATTR_CURVE_ED448:
				*psa_alg = PSA_ALG_ED448PH;
				break;

			case SMW_ATTR_CURVE_ANY:
				*psa_alg = PSA_ALG_PURE_EDDSA;
				break;

			default:
				goto end;
			}
		} else if ((algo == SMW_ATTR_ALGO_RSA) &&
			   (mode == SMW_ATTR_MODE_PKCS1_1_5)) {
			if (hash == SMW_ATTR_HASH_NONE)
				*psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN_RAW;
			else
				*psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(psa_hash);
		}
		break;

	case SMW_ATTR_CLASS_MAC:
		if (algo == SMW_ATTR_ALGO_AES || algo == SMW_ATTR_ALGO_DES ||
		    algo == SMW_ATTR_ALGO_DES3)
			if (mode == SMW_ATTR_MODE_CMAC)
				*psa_alg = PSA_ALG_CMAC;
			else
				*psa_alg = PSA_ALG_CBC_MAC;
		else if (algo == SMW_ATTR_ALGO_HMAC)
			*psa_alg = PSA_ALG_HMAC(psa_hash);
		break;

	case SMW_ATTR_CLASS_AEAD:
		if (algo == SMW_ATTR_ALGO_AES) {
			if (mode == SMW_ATTR_MODE_CCM)
				*psa_alg = PSA_ALG_CCM;
			else if (mode == SMW_ATTR_MODE_GCM)
				*psa_alg = PSA_ALG_GCM;
		} else if (algo == SMW_ATTR_ALGO_CHACHA20) {
			*psa_alg = PSA_ALG_CHACHA20_POLY1305;
		}
		break;

	case SMW_ATTR_CLASS_KEY_DERIVATION:
		*psa_alg = get_psa_kdf_algo(algo, psa_hash);
		break;

	case SMW_ATTR_CLASS_KEY_AGREEMENT:
		if (algo == SMW_ATTR_ALGO_ECDH)
			*psa_alg = PSA_ALG_ECDH;

		break;

	default:
		SMW_DBG_PRINTF(ERROR, "%s Unknown algorithm 0x%" PRIx64 "\n",
			       __func__, permitted_algo);
		goto end;
	}

	SMW_DBG_PRINTF(DEBUG, "Key main algorithm: 0x%" PRIx64 "(0x%.8x)\n",
		       permitted_algo, *psa_alg);

	if (PSA_ALG_IS_AEAD(*psa_alg))
		set_aead_tag_length(psa_alg, length, is_min_length);
	else if (PSA_ALG_IS_MAC(*psa_alg))
		set_mac_length(psa_alg, length, is_min_length);

	psa_status = PSA_SUCCESS;

end:
	return psa_status;
}

static smw_attr_algo_t get_smw_algo(psa_algorithm_t psa_alg,
				    smw_key_type_t key_type)
{
	smw_attr_algo_t smw_algo = 0;

	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_attr_algo_t mode = SMW_ATTR_MODE_NONE;
	smw_attr_algo_t curve = SMW_ATTR_CURVE_NONE;
	smw_attr_algo_t hash = SMW_ATTR_HASH_NONE;
	smw_attr_algo_t class = SMW_ATTR_CLASS_NONE;
	smw_attr_algo_t length = 0;
	smw_attr_algo_t min_length = 0;
	psa_algorithm_t psa_alg_base = PSA_ALG_NONE;

	uint8_t l = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!psa_alg)
		goto end;

	switch (psa_alg & PSA_ALG_CATEGORY_MASK) {
	case PSA_ALG_CATEGORY_AEAD:
		class = SMW_ATTR_CLASS_AEAD;
		algo = get_cipher_algo_key_type(key_type);
		psa_alg_base = PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(psa_alg);

		switch (psa_alg_base) {
		case PSA_ALG_CCM:
			mode = SMW_ATTR_MODE_CCM;
			break;

		case PSA_ALG_GCM:
			mode = SMW_ATTR_MODE_GCM;
			break;

		case PSA_ALG_CHACHA20_POLY1305:
			mode = SMW_ATTR_MODE_POLY1305;
			break;
		}

		l = (psa_alg & PSA_ALG_AEAD_TAG_LENGTH_MASK) >>
		    PSA_AEAD_TAG_LENGTH_OFFSET;

		if (psa_alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG)
			min_length = l;
		else
			length = l;

		break;

	case PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION:
		class = SMW_ATTR_CLASS_ASYMMETRIC_ENCRYPTION;
		algo = SMW_ATTR_ALGO_RSA;
		if (PSA_ALG_IS_RSA_OAEP(psa_alg)) {
			hash = get_smw_hash(PSA_ALG_GET_HASH(psa_alg));
			mode = SMW_ATTR_MODE_OAEP;
		} else {
			mode = SMW_ATTR_MODE_PKCS1_1_5;
		}

		break;

	case PSA_ALG_CATEGORY_CIPHER:
		class = SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION;
		algo = get_cipher_algo_key_type(key_type);
		mode = get_smw_cipher_mode(psa_alg);
		break;

	case PSA_ALG_CATEGORY_MAC:
		class = SMW_ATTR_CLASS_MAC;
		if (PSA_ALG_IS_HMAC(psa_alg)) {
			algo = SMW_ATTR_ALGO_HMAC;
			hash = get_smw_hash(PSA_ALG_GET_HASH(psa_alg));
		} else {
			mode = SMW_ATTR_MODE_CMAC;
			algo = get_cipher_algo_key_type(key_type);
		}

		l = (psa_alg & PSA_ALG_MAC_TRUNCATION_MASK) >>
		    PSA_MAC_TRUNCATION_OFFSET;

		if (psa_alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG)
			min_length = l;
		else
			length = l;

		break;

	case PSA_ALG_CATEGORY_SIGN:
		class = SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE;
		hash = get_smw_hash(PSA_ALG_GET_HASH(psa_alg));

		if (PSA_ALG_IS_ECDSA(psa_alg)) {
			algo = SMW_ATTR_ALGO_ECDSA;
			curve = SMW_ATTR_CURVE_ANY;
		} else if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(psa_alg)) {
			algo = SMW_ATTR_ALGO_RSA;
			mode = SMW_ATTR_MODE_PKCS1_1_5;
		} else if (PSA_ALG_IS_RSA_PSS(psa_alg)) {
			algo = SMW_ATTR_ALGO_RSA;
			mode = SMW_ATTR_MODE_PSS;
		} else if (psa_alg == PSA_ALG_PURE_EDDSA) {
			algo = SMW_ATTR_ALGO_EDDSA;
			curve = SMW_ATTR_CURVE_ANY;
			hash = SMW_ATTR_HASH_NONE;
		} else if (psa_alg == PSA_ALG_ED25519PH) {
			algo = SMW_ATTR_ALGO_EDDSA;
			curve = SMW_ATTR_CURVE_ED25519;
			hash = SMW_ATTR_HASH_NONE;
		} else if (psa_alg == PSA_ALG_ED448PH) {
			algo = SMW_ATTR_ALGO_EDDSA;
			curve = SMW_ATTR_CURVE_ED448;
			hash = SMW_ATTR_HASH_NONE;
		}

		break;

	case PSA_ALG_CATEGORY_KEY_DERIVATION:
		class = SMW_ATTR_CLASS_KEY_DERIVATION;
		hash = get_smw_hash(PSA_ALG_GET_HASH(psa_alg));

		psa_alg_base = psa_alg;
		CLEAR_BITS(psa_alg_base, PSA_ALG_HASH_MASK);
		algo = get_smw_kdf_algo(psa_alg_base);

		break;

	default:
		goto end;
	}

	smw_algo = (((class & SMW_ATTR_CLASS_MASK) << SMW_ATTR_CLASS_OFFSET) |
		    ((algo & SMW_ATTR_ALGO_MASK) << SMW_ATTR_ALGO_OFFSET));

	if (mode != SMW_ATTR_MODE_NONE)
		smw_algo |=
			((mode & (SMW_ATTR_MODE_MASK)) << SMW_ATTR_MODE_OFFSET);

	if (curve != SMW_ATTR_CURVE_NONE)
		smw_algo |= ((curve & (SMW_ATTR_CURVE_MASK))
			     << SMW_ATTR_CURVE_OFFSET);

	if (hash != SMW_ATTR_HASH_NONE)
		smw_algo |=
			((hash & (SMW_ATTR_HASH_MASK)) << SMW_ATTR_HASH_OFFSET);

	if (min_length)
		smw_algo = SMW_ATTR_SET_MIN_LENGTH(smw_algo, min_length);
	else if (length)
		smw_algo = SMW_ATTR_SET_LENGTH(smw_algo, length);

end:
	SMW_DBG_PRINTF(DEBUG, "Key algorithm: 0x%.8x -> 0x%" PRIx64 "\n",
		       psa_alg, smw_algo);

	return smw_algo;
}

static psa_status_t
set_key_attributes(const psa_key_attributes_t *psa_attributes,
		   struct smw_key_descriptor *smw_key_descriptor)
{
	struct smw_key_attributes *smw_attributes = NULL;

	psa_algorithm_t algorithm = PSA_ALG_NONE;
	psa_key_usage_t usage_flags = 0;
	psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_VOLATILE;
	smw_attr_attributes_t persistence = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!psa_attributes || !smw_key_descriptor)
		return PSA_ERROR_INVALID_ARGUMENT;

	smw_key_descriptor->type_name =
		get_smw_key_type(psa_attributes,
				 smw_key_descriptor->security_size);
	if (smw_key_descriptor->type_name == SMW_KEY_TYPE_NAME_NONE)
		return PSA_ERROR_NOT_SUPPORTED;

	algorithm = psa_get_key_algorithm(psa_attributes);
	usage_flags = psa_get_key_usage_flags(psa_attributes);
	lifetime = psa_get_key_lifetime(psa_attributes);

	smw_attributes = &smw_key_descriptor->attributes;

	smw_attributes->permitted_algo =
		get_smw_algo(algorithm, smw_key_descriptor->type_name);
	smw_attributes->usage_flags = get_smw_usage_flags(usage_flags);
	smw_attributes->storage_id = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
	persistence = get_smw_persistence(lifetime);
	smw_attributes->attributes =
		SMW_ATTR_SET_PERSISTENCE(smw_attributes->attributes,
					 persistence);

	return PSA_SUCCESS;
}

static psa_status_t
read_key_attributes(psa_key_attributes_t *psa_attributes,
		    struct smw_key_attributes *smw_attributes)
{
	int psa_status = PSA_ERROR_DATA_INVALID;
	psa_key_usage_t usage_flags = 0;
	psa_algorithm_t perm_algo = PSA_ALG_NONE;
	psa_key_persistence_t persistence = PSA_KEY_PERSISTENCE_VOLATILE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_attributes)
		goto end;

	usage_flags = get_psa_usage_flags(smw_attributes->usage_flags);

	psa_status = get_psa_alg(&perm_algo, smw_attributes->permitted_algo);
	if (psa_status != PSA_SUCCESS)
		goto end;

	psa_status =
		get_psa_persistence(&persistence, smw_attributes->attributes);
	if (psa_status != PSA_SUCCESS)
		goto end;

	psa_set_key_usage_flags(psa_attributes, usage_flags);
	psa_set_key_algorithm(psa_attributes, perm_algo);

	psa_attributes->lifetime =
		PSA_KEY_LIFETIME_GET_LIFETIME(persistence,
					      smw_attributes->storage_id);

	psa_status = PSA_SUCCESS;

end:
	return psa_status;
}

static psa_status_t
encode_asn1_rsa_public_key(uint8_t *data, size_t data_size, size_t *data_length,
			   struct smw_keypair_rsa *keypair_rsa)
{
	struct asn1_integer sequence[2] = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_size || !data_length || !keypair_rsa)
		return PSA_ERROR_INVALID_ARGUMENT;

	/* RSA KEY */
	sequence[0].length = keypair_rsa->modulus_length;
	sequence[0].value = keypair_rsa->modulus;
	sequence[1].length = keypair_rsa->public_length;
	sequence[1].value = keypair_rsa->public_data;

	/*
	 *	RSAPublicKey ::= SEQUENCE {
	 *	   modulus            INTEGER,    -- n
	 *	   publicExponent     INTEGER  }  -- e
	 */
	*data_length = asn1_encode_sequence_integer(data, data_size, sequence,
						    ARRAY_SIZE(sequence));

	return *data_length ? PSA_SUCCESS : PSA_ERROR_BUFFER_TOO_SMALL;
}

static psa_status_t export_rsa_public_key(uint8_t *data, size_t data_size,
					  size_t *data_length,
					  struct smw_export_key_args *args)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_keypair_rsa *keypair_rsa = NULL;
	uint8_t *modulus = NULL;
	uint8_t *public_data = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_size || !data_length || !args ||
	    !args->key_descriptor || !args->key_descriptor->buffer)
		return psa_status;

	keypair_rsa = &args->key_descriptor->buffer->rsa;

	modulus = SMW_UTILS_MALLOC(keypair_rsa->modulus_length);
	if (!modulus)
		return PSA_ERROR_INSUFFICIENT_MEMORY;

	public_data = SMW_UTILS_MALLOC(keypair_rsa->public_length);
	if (!public_data) {
		psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
		goto end;
	}

	keypair_rsa->modulus = modulus;
	keypair_rsa->public_data = public_data;

	status = smw_export_key(args);
	if (status != SMW_STATUS_OK) {
		psa_status = util_smw_to_psa_status(status);
		goto end;
	}

	psa_status = encode_asn1_rsa_public_key(data, data_size, data_length,
						keypair_rsa);

end:
	if (modulus)
		SMW_UTILS_FREE(modulus);

	if (public_data)
		SMW_UTILS_FREE(public_data);

	return psa_status;
}

static psa_status_t export_ecc_public_key(uint8_t *data, size_t data_size,
					  size_t *data_length,
					  struct smw_export_key_args *args)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_keypair_gen *keypair_gen = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_size || !data_length || !args ||
	    !args->key_descriptor || !args->key_descriptor->buffer)
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_gen = &args->key_descriptor->buffer->gen;

	*data_length = keypair_gen->public_length + 1;
	keypair_gen->public_data = data + 1;
	*data = 0x04;

	if (data_size < *data_length)
		return PSA_ERROR_BUFFER_TOO_SMALL;

	status = smw_export_key(args);

	return util_smw_to_psa_status(status);
}

static psa_status_t export_gen_public_key(uint8_t *data, size_t data_size,
					  size_t *data_length,
					  struct smw_export_key_args *args)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_keypair_gen *keypair_gen = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_size || !data_length || !args ||
	    !args->key_descriptor || !args->key_descriptor->buffer)
		return PSA_ERROR_INVALID_ARGUMENT;

	keypair_gen = &args->key_descriptor->buffer->gen;

	*data_length = keypair_gen->public_length;
	keypair_gen->public_data = data;

	if (data_size < *data_length)
		return PSA_ERROR_BUFFER_TOO_SMALL;

	status = smw_export_key(args);

	return util_smw_to_psa_status(status);
}

static psa_status_t export_key_common(psa_key_id_t key, uint8_t *data,
				      size_t data_size, size_t *data_length)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_export_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };
	struct smw_get_key_attributes_args attr_args = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	if (!data || !data_size || !data_length)
		return PSA_ERROR_INVALID_ARGUMENT;

	key_descriptor.id = key;

	attr_args.subsystem_name = get_psa_default_subsystem();
	attr_args.key_descriptor = &key_descriptor;

	status = smw_get_key_attributes(&attr_args);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor.buffer = &keypair_buffer;
	status = smw_get_key_buffers_lengths(&key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	args.key_descriptor = &key_descriptor;

	if (key_descriptor.type_name == SMW_KEY_TYPE_NAME_RSA) {
		return export_rsa_public_key(data, data_size, data_length,
					     &args);
	} else {
		if (!keypair_buffer.gen.public_length)
			return PSA_ERROR_INVALID_ARGUMENT;

		if (is_ecc_key_type(key_descriptor.type_name)) {
			return export_ecc_public_key(data, data_size,
						     data_length, &args);
		} else {
			return export_gen_public_key(data, data_size,
						     data_length, &args);
		}
	}

end:
	return util_smw_to_psa_status(status);
}

__export psa_status_t psa_copy_key(psa_key_id_t source_key,
				   const psa_key_attributes_t *attributes,
				   psa_key_id_t *target_key)
{
	(void)source_key;
	(void)attributes;
	(void)target_key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_destroy_key(psa_key_id_t key)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_delete_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	if (key == PSA_KEY_ID_NULL)
		return PSA_SUCCESS;

	key_descriptor.id = key;
	args.key_descriptor = &key_descriptor;

	status = smw_delete_key(&args);

	return util_smw_to_psa_status(status);
}

__export psa_status_t psa_export_key(psa_key_id_t key, uint8_t *data,
				     size_t data_size, size_t *data_length)
{
	return export_key_common(key, data, data_size, data_length);
}

__export psa_status_t psa_export_public_key(psa_key_id_t key, uint8_t *data,
					    size_t data_size,
					    size_t *data_length)
{
	return export_key_common(key, data, data_size, data_length);
}

__export psa_status_t psa_generate_key(const psa_key_attributes_t *attributes,
				       psa_key_id_t *key)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_generate_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	size_t security_size = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!attributes || !key)
		return PSA_ERROR_INVALID_ARGUMENT;

	key_descriptor.id = psa_get_key_id(attributes);
	security_size = psa_get_key_bits(attributes);

	if (SET_OVERFLOW(security_size, key_descriptor.security_size))
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status = set_key_attributes(attributes, &key_descriptor);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	args.key_descriptor = &key_descriptor;

	psa_status =
		call_smw_api((enum smw_status_code(*)(void *))smw_generate_key,
			     &args, &args.subsystem_name);

	if (psa_status == PSA_SUCCESS)
		*key = key_descriptor.id;
	else
		*key = PSA_KEY_ID_NULL;

	return psa_status;
}

__export psa_status_t psa_get_key_attributes(psa_key_id_t key,
					     psa_key_attributes_t *attributes)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_get_key_attributes_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	psa_key_type_t key_type = PSA_KEY_TYPE_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!attributes || !key)
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_reset_key_attributes(attributes);

	key_descriptor.id = key;

	args.subsystem_name = get_psa_default_subsystem();
	args.key_descriptor = &key_descriptor;

	status = smw_get_key_attributes(&args);
	psa_status = util_smw_to_psa_status(status);
	if (psa_status != PSA_SUCCESS)
		goto exit;

	psa_set_key_id(attributes, args.key_descriptor->id);

	psa_status = get_psa_key_type(&key_type, key_descriptor.type_name,
				      args.key_privacy_name);
	if (psa_status != PSA_SUCCESS)
		goto exit;

	psa_set_key_type(attributes, key_type);

	psa_set_key_bits(attributes, args.key_descriptor->security_size);

	psa_status =
		read_key_attributes(attributes, &key_descriptor.attributes);

exit:
	return psa_status;
}

__export psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
				     const uint8_t *data, size_t data_length,
				     psa_key_id_t *key)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	struct smw_import_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };
	struct smw_keypair_gen *keypair_gen = NULL;
	psa_key_type_t key_type = 0;
	size_t security_size = 0;
	unsigned int location = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return psa_status;

	if (!attributes || !data || !data_length || !key)
		return PSA_ERROR_INVALID_ARGUMENT;

	key_descriptor.buffer = &keypair_buffer;

	key_descriptor.id = psa_get_key_id(attributes);

	key_type = psa_get_key_type(attributes);
	location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

	/*
	 * Check first if it's a NXP EdgeLock 2GO object to set
	 * the import data as SMW key private buffer.
	 * If it's not a NXP EdgeLock 2GO object set the SMW key buffers
	 * function of the key type.
	 */
	if (NXP_IS_EL2GO_OBJECT(location)) {
		keypair_gen = &keypair_buffer.gen;
		set_gen_private_key_buffer(data, data_length, keypair_gen);
		security_size = psa_get_key_bits(attributes);
	} else if (PSA_KEY_TYPE_IS_RSA(key_type)) {
		psa_status = set_rsa_key_buffer(key_type, data, data_length,
						&keypair_buffer.rsa);
		if (psa_status != PSA_SUCCESS)
			return psa_status;

		security_size =
			BYTES_TO_BITS(keypair_buffer.rsa.modulus_length);
	} else if (PSA_KEY_TYPE_IS_ECC(key_type)) {
		keypair_gen = &keypair_buffer.gen;

		set_ecc_key_buffer(key_type, data, data_length, keypair_gen);

		if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(key_type))
			security_size =
				BYTES_TO_BITS(keypair_gen->public_length / 2);
		else
			security_size =
				BYTES_TO_BITS(keypair_gen->private_length);
	} else if (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type)) {
		keypair_gen = &keypair_buffer.gen;

		set_gen_private_key_buffer(data, data_length, keypair_gen);

		security_size = BYTES_TO_BITS(keypair_gen->private_length);
	} else {
		return PSA_ERROR_NOT_SUPPORTED;
	}

	if (psa_get_key_bits(attributes) &&
	    security_size != psa_get_key_bits(attributes))
		return PSA_ERROR_INVALID_ARGUMENT;

	if (key_type == PSA_KEY_TYPE_DES)
		security_size = security_size / 8 * 7;

	if (PSA_KEY_TYPE_IS_ECC(key_type) &&
	    PSA_KEY_TYPE_ECC_GET_FAMILY(key_type) == PSA_ECC_FAMILY_SECP_R1 &&
	    security_size == 528)
		security_size = 521;

	if (SET_OVERFLOW(security_size, key_descriptor.security_size))
		return PSA_ERROR_INVALID_ARGUMENT;

	psa_status = set_key_attributes(attributes, &key_descriptor);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	args.key_descriptor = &key_descriptor;

	psa_status =
		call_smw_api((enum smw_status_code(*)(void *))smw_import_key,
			     &args, &args.subsystem_name);

	if (psa_status == PSA_SUCCESS)
		*key = key_descriptor.id;
	else
		*key = PSA_KEY_ID_NULL;

	return psa_status;
}

__export psa_status_t
psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (operation->info)
		SMW_UTILS_FREE(operation->info);

	if (operation->peerbuf)
		SMW_UTILS_FREE(operation->peerbuf);

	memset(operation, 0, sizeof(*operation));

	return PSA_SUCCESS;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_get_capacity(const psa_key_derivation_operation_t *operation,
				size_t *capacity)
{
	(void)operation;
	(void)capacity;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

extern smw_hash_algo_t get_hash_algo_name(psa_algorithm_t alg);

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
			       psa_key_derivation_step_t step,
			       const uint8_t *data, size_t data_length)
{
	psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_ALG_IS_VENDOR_TLS13(operation->alg) &&
	    step == PSA_KEY_DERIVATION_INPUT_INFO) {
		if (operation->info || operation->infolen) {
			psa_status = PSA_ERROR_ALREADY_EXISTS;
		} else {
			if (!data || !data_length)
				return PSA_ERROR_INVALID_ARGUMENT;

			operation->infolen = data_length;
			operation->info = SMW_UTILS_MALLOC(operation->infolen);
			if (!operation->info) {
				psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
			} else {
				SMW_UTILS_MEMCPY(operation->info, data,
						 operation->infolen);

				psa_status = PSA_SUCCESS;
			}
		}
	}
	return psa_status;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_input_integer(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step, uint64_t value)
{
	(void)operation;
	(void)step;
	(void)value;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_key_derivation_input_key(psa_key_derivation_operation_t *operation,
			     psa_key_derivation_step_t step, psa_key_id_t key)
{
	psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_ALG_IS_VENDOR_TLS13(operation->alg)) {
		if (step == PSA_KEY_DERIVATION_INPUT_SECRET) {
			if (operation->secret_id) {
				psa_status = PSA_ERROR_ALREADY_EXISTS;
			} else {
				operation->secret_id = key;
				psa_status = PSA_SUCCESS;
			}
		} else if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET) {
			if (operation->other_secret_id) {
				psa_status = PSA_ERROR_ALREADY_EXISTS;
			} else {
				operation->other_secret_id = key;
				psa_status = PSA_SUCCESS;
			}
		}
	}

	return psa_status;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 psa_key_id_t private_key,
				 const uint8_t *peer_key,
				 size_t peer_key_length)
{
	psa_status_t psa_status = PSA_ERROR_NOT_SUPPORTED;
	psa_key_attributes_t private_attr = psa_key_attributes_init();
	bool skip_bytes = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_ALG_IS_VENDOR_TLS13(operation->alg)) {
		if (step == PSA_KEY_DERIVATION_INPUT_OTHER_SECRET) {
			if (operation->other_secret_id || operation->peerbuf ||
			    operation->peerbuflen)
				return PSA_ERROR_ALREADY_EXISTS;

			psa_status = psa_get_key_attributes(private_key,
							    &private_attr);
			if (psa_status != PSA_SUCCESS)
				return psa_status;

			if (!PSA_ALG_IS_VENDOR_TLS13(private_attr.alg))
				return PSA_ERROR_NOT_PERMITTED;

			if (PSA_KEY_TYPE_IS_ECC(private_attr.type) &&
			    PSA_KEY_TYPE_ECC_GET_FAMILY(private_attr.type) ==
				    PSA_ECC_FAMILY_SECP_R1 &&
			    peer_key[0] == 0x04) {
				/*
				 * SECP_R1 keys should be in uncompressed format with a 0x04
				 * leading byte. Skip the leading byte in this case.
				 */
				skip_bytes = 1;
			}

			operation->other_secret_id = private_key;
			operation->peerbuflen = peer_key_length - skip_bytes;
			operation->peerbuf =
				SMW_UTILS_MALLOC(operation->peerbuflen);
			if (!operation->peerbuf)
				return PSA_ERROR_INSUFFICIENT_MEMORY;

			SMW_UTILS_MEMCPY(operation->peerbuf,
					 peer_key + skip_bytes,
					 operation->peerbuflen);

			psa_status = PSA_SUCCESS;
		}
	}

	return psa_status;
}

static psa_status_t
psa_key_derivation_output_tls13(const psa_key_attributes_t *attributes,
				psa_key_derivation_operation_t *operation,
				psa_key_id_t *key, uint8_t *output,
				size_t output_length)
{
	struct smw_kdf_tls13_args tls13 = { 0 };
	struct smw_key_descriptor base = { 0 };
	struct smw_key_descriptor psk = { 0 };
	struct smw_derived_key_descriptor derived = { 0 };
	struct smw_derive_key_args derive = { 0 };
	enum smw_status_code status = SMW_STATUS_OK;
	psa_key_attributes_t *attr = (psa_key_attributes_t *)attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (operation->other_secret_id) {
		base.id = operation->other_secret_id;
		derive.store_derived_key = true;
	} else {
		base.type_name = SMW_KEY_TYPE_NAME_DERIVE;
	}

	if (SET_OVERFLOW(operation->infolen, tls13.expanded_label_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	tls13.expanded_label = operation->info;

	if (SET_OVERFLOW(operation->peerbuflen,
			 tls13.peer_public_buffer_length))
		return PSA_ERROR_INVALID_ARGUMENT;

	tls13.peer_public_buffer = operation->peerbuf;

	tls13.prf_name = get_hash_algo_name(PSA_ALG_GET_HASH(operation->alg));

	if (operation->secret_id) {
		psk.id = operation->secret_id;
		tls13.psk = &psk;
	}

	if (key) {
		if (SET_OVERFLOW(attr->bits, derived.security_size))
			return PSA_ERROR_INVALID_ARGUMENT;

		derived.type_name =
			get_smw_key_type(attr, derived.security_size);

		if (derived.type_name == SMW_KEY_TYPE_NAME_NONE)
			return PSA_ERROR_NOT_SUPPORTED;

		derived.attributes.usage_flags =
			get_smw_usage_flags(attr->usage_flags);
		derived.attributes.permitted_algo =
			get_smw_algo(attr->alg, derived.type_name);
	} else {
		if (SET_OVERFLOW(output_length, derived.shared_secret_len))
			return PSA_ERROR_INVALID_ARGUMENT;

		derived.shared_secret = output;
	}

	derive.kdf_name = SMW_KDF_NAME_TLS13_KEY_EXCHANGE;
	derive.kdf_arguments = &tls13;
	derive.subsystem_name = get_psa_default_subsystem();
	derive.key_descriptor_base = &base;
	derive.key_descriptor_derived = &derived;

	status = smw_derive_key(&derive);
	if (status != SMW_STATUS_OK)
		return util_smw_to_psa_status(status);

	if (key)
		*key = derived.id;

	return PSA_SUCCESS;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_output_common(const psa_key_attributes_t *attributes,
				 psa_key_derivation_operation_t *operation,
				 psa_key_id_t *key, uint8_t *output,
				 size_t output_length)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_ALG_IS_VENDOR_TLS13(operation->alg))
		return psa_key_derivation_output_tls13(attributes, operation,
						       key, output,
						       output_length);

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
				uint8_t *output, size_t output_length)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!operation)
		return PSA_ERROR_BAD_STATE;

	if (!output || !output_length)
		return PSA_ERROR_INSUFFICIENT_DATA;

	return psa_key_derivation_output_common(NULL, operation, NULL, output,
						output_length);
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
			      psa_key_derivation_operation_t *operation,
			      psa_key_id_t *key)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attributes || !key)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (!operation)
		return PSA_ERROR_BAD_STATE;

	return psa_key_derivation_output_common(attributes, operation, key,
						NULL, 0);
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_set_capacity(psa_key_derivation_operation_t *operation,
				size_t capacity)
{
	(void)operation;
	(void)capacity;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_setup(psa_key_derivation_operation_t *operation,
			 psa_algorithm_t alg)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_ALG_IS_VENDOR_TLS13(alg)) {
		if (PSA_ALG_GET_HASH(alg) != PSA_ALG_SHA_256 &&
		    PSA_ALG_GET_HASH(alg) != PSA_ALG_SHA_384)
			return PSA_ERROR_NOT_SUPPORTED;

		operation->alg = alg;
		return PSA_SUCCESS;
	}

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_verify_bytes(psa_key_derivation_operation_t *operation,
				const uint8_t *expected_output,
				size_t output_length)
{
	(void)operation;
	(void)expected_output;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_verify_key(psa_key_derivation_operation_t *operation,
			      psa_key_id_t expected)
{
	(void)operation;
	(void)expected;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
	*attributes = PSA_KEY_ATTRIBUTES_INIT;

	SMW_DBG_TRACE_FUNCTION_CALL;
}
