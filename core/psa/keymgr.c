// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "smw_keymgr.h"

#include "psa/crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "tlv.h"

#include "asn1.h"
#include "common.h"
#include "util_status.h"

#define KEY_TYPE(_smw, _psa)                                                   \
	{                                                                      \
		.smw_key_type = _smw, .psa_key_type = PSA_KEY_TYPE_##_psa,     \
	}

/**
 * struct - Key type
 * @smw_key_type: SMW key type name.
 * @psa_key_type: PSA key type.
 */
static const struct cipher_key_type {
	smw_key_type_t smw_key_type;
	psa_key_type_t psa_key_type;
} cipher_key_type[] = { KEY_TYPE("AES", AES), KEY_TYPE("DES", DES),
			KEY_TYPE("DES3", DES), KEY_TYPE("SM4", SM4) };

#define HMAC_HASH(_smw, _psa)                                                  \
	{                                                                      \
		.smw_key_type = _smw, .psa_hash = PSA_ALG_##_psa               \
	}

/**
 * struct - HMAC hash
 * @smw_key_type: SMW HMAC key type name.
 * @psa_hash: PSA hash id.
 */
static const struct {
	smw_key_type_t smw_key_type;
	psa_algorithm_t psa_hash;
} hmac_hash[] = {
	HMAC_HASH("HMAC", NONE),	   HMAC_HASH("HMAC_MD5", MD5),
	HMAC_HASH("HMAC_SHA1", SHA_1),	   HMAC_HASH("HMAC_SHA224", SHA_224),
	HMAC_HASH("HMAC_SHA256", SHA_256), HMAC_HASH("HMAC_SHA384", SHA_384),
	HMAC_HASH("HMAC_SHA512", SHA_512), HMAC_HASH("HMAC_SM3", SM3)
};

#define ECC_KEY_TYPE(_smw, _family)                                            \
	{                                                                      \
		.smw_key_type = _smw, .ecc_family = PSA_ECC_FAMILY_##_family   \
	}

/**
 * struct - ECC key type
 * @smw_key_type: SMW HMAC key type name.
 * @ecc_family: Elliptic curve family.
 */
struct ecc_key_type {
	smw_key_type_t smw_key_type;
	psa_ecc_family_t ecc_family;
};

static const struct ecc_key_type ecdsa_key_type[] = {
	ECC_KEY_TYPE("NIST", SECP_R1),
	ECC_KEY_TYPE("BRAINPOOL_R1", BRAINPOOL_P_R1)
};

static const struct ecc_key_type ecdh_key_type[] = {
	ECC_KEY_TYPE("ECDH_NIST", SECP_R1),
	ECC_KEY_TYPE("ECDH_BRAINPOOL_R1", BRAINPOOL_P_R1)
};

#define KEY_USAGE(_name, _restricted)                                          \
	{                                                                      \
		.usage_str = _name##_STR, .psa_usage = PSA_KEY_USAGE_##_name,  \
		.restricted = _restricted                                      \
	}

/**
 * struct - Key usage
 * @usage_str: SMW usage name used for TLV encoding.
 * @psa_usage: PSA usage id.
 * @restricted: Is usage restricted to an algorithm.
 */
static const struct {
	const char *usage_str;
	psa_key_usage_t psa_usage;
	bool restricted;
} key_usage[] = {
	KEY_USAGE(EXPORT, false),      KEY_USAGE(COPY, false),
	KEY_USAGE(ENCRYPT, true),      KEY_USAGE(DECRYPT, true),
	KEY_USAGE(SIGN_MESSAGE, true), KEY_USAGE(VERIFY_MESSAGE, true),
	KEY_USAGE(SIGN_HASH, true),    KEY_USAGE(VERIFY_HASH, true),
	KEY_USAGE(DERIVE, true)
};

#define KEY_ALGORITHM(_name)                                                   \
	{                                                                      \
		.alg_str = _name##_STR, .psa_alg = PSA_ALG_##_name             \
	}

/**
 * struct - Key algorithm
 * @alg_str: SMW algorithm name used for TLV encoding.
 * @psa_alg: PSA algorithm id.
 */
static const struct {
	const char *alg_str;
	psa_algorithm_t psa_alg;
} key_algorithm[] = { KEY_ALGORITHM(CBC_MAC),
		      KEY_ALGORITHM(CMAC),
		      KEY_ALGORITHM(STREAM_CIPHER),
		      KEY_ALGORITHM(CTR),
		      KEY_ALGORITHM(CFB),
		      KEY_ALGORITHM(OFB),
		      KEY_ALGORITHM(XTS),
		      KEY_ALGORITHM(ECB_NO_PADDING),
		      KEY_ALGORITHM(CBC_NO_PADDING),
		      KEY_ALGORITHM(CBC_PKCS7),
		      KEY_ALGORITHM(CCM),
		      KEY_ALGORITHM(GCM),
		      KEY_ALGORITHM(CHACHA20_POLY1305),
		      KEY_ALGORITHM(PURE_EDDSA),
		      KEY_ALGORITHM(ED25519PH),
		      KEY_ALGORITHM(ED448PH),
		      KEY_ALGORITHM(RSA_PKCS1V15_CRYPT),
		      KEY_ALGORITHM(ECDH),
		      KEY_ALGORITHM(FFDH) };

#define KEY_HASH(_name)                                                        \
	{                                                                      \
		.hash_str = _name##_STR, .psa_hash = PSA_ALG_##_name           \
	}

/**
 * struct - Key hash
 * @hash_str: SMW hash name used for TLV encoding.
 * @psa_hash: PSA hash id.
 */
static const struct {
	const char *hash_str;
	psa_algorithm_t psa_hash;
} key_hash[] = {
	KEY_HASH(MD2),		KEY_HASH(MD4),	       KEY_HASH(MD5),
	KEY_HASH(RIPEMD160),	KEY_HASH(SHA_1),       KEY_HASH(SHA_224),
	KEY_HASH(SHA_256),	KEY_HASH(SHA_384),     KEY_HASH(SHA_512),
	KEY_HASH(SHA_512_224),	KEY_HASH(SHA_512_256), KEY_HASH(SHA3_224),
	KEY_HASH(SHA3_256),	KEY_HASH(SHA3_384),    KEY_HASH(SHA3_512),
	KEY_HASH(SHAKE256_512), KEY_HASH(SM3)
};

static const struct key_persistence {
	const char *str;
	psa_key_persistence_t persistence;
} key_persistences[] = {
	{ "TRANSIENT", PSA_KEY_PERSISTENCE_VOLATILE },
	{ "PERSISTENT", PSA_KEY_PERSISTENCE_DEFAULT },
	{ "PERMANENT", PSA_KEY_PERSISTENCE_READ_ONLY },
};

static bool is_ecc_key_type(smw_key_type_t type_name)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!type_name)
		return false;

	if (!SMW_UTILS_STRCMP(type_name, "NIST") ||
	    !SMW_UTILS_STRCMP(type_name, "BRAINPOOL_R1") ||
	    !SMW_UTILS_STRCMP(type_name, "BRAINPOOL_T1") ||
	    !SMW_UTILS_STRCMP(type_name, "ECDH_NIST") ||
	    !SMW_UTILS_STRCMP(type_name, "ECDH_BRAINPOOL_R1") ||
	    !SMW_UTILS_STRCMP(type_name, "ECDH_BRAINPOOL_T1"))
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
	keypair_rsa->modulus_length = sequence[1].length;
	keypair_rsa->public_data = sequence[2].value;
	keypair_rsa->public_length = sequence[2].length;
	keypair_rsa->private_data = sequence[3].value;
	keypair_rsa->private_length = sequence[3].length;

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
	keypair_rsa->modulus_length = sequence[0].length;
	keypair_rsa->public_data = sequence[1].value;
	keypair_rsa->public_length = sequence[1].length;

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
	keypair_gen->private_length = data_length;
}

static void set_ecc_public_key_buffer(const uint8_t *data, size_t data_length,
				      struct smw_keypair_gen *keypair_gen)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	/* Remove byte 0x04 */
	keypair_gen->public_data = (unsigned char *)data + 1;
	keypair_gen->public_length = data_length - 1;
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

static smw_key_type_t get_hmac_smw_key_type(psa_algorithm_t psa_hash)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(hmac_hash); i++) {
		if (hmac_hash[i].psa_hash == psa_hash)
			return hmac_hash[i].smw_key_type;
	}

	return NULL;
}

static smw_key_type_t get_ecc_smw_key_type(psa_ecc_family_t ecc_family,
					   psa_algorithm_t psa_hash)
{
	unsigned int i;
	unsigned int array_size = 0;
	const struct ecc_key_type *array = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!psa_hash || PSA_ALG_IS_ECDSA(psa_hash)) {
		array_size = ARRAY_SIZE(ecdsa_key_type);
		array = ecdsa_key_type;
	} else if (PSA_ALG_IS_ECDH(psa_hash)) {
		array_size = ARRAY_SIZE(ecdh_key_type);
		array = ecdh_key_type;
	}

	for (i = 0; i < array_size; i++) {
		if (array[i].ecc_family == ecc_family)
			return array[i].smw_key_type;
	}

	return NULL;
}

static psa_key_type_t get_ecc_psa_key_type(smw_key_type_t smw_key_type,
					   bool is_keypair)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	psa_ecc_family_t ecc_family = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; !ecc_family && i < ARRAY_SIZE(ecdsa_key_type); i++) {
		if (!SMW_UTILS_STRCMP(ecdsa_key_type[i].smw_key_type,
				      smw_key_type))
			ecc_family = ecdsa_key_type[i].ecc_family;
	}

	for (i = 0; !ecc_family && i < ARRAY_SIZE(ecdh_key_type); i++) {
		if (!SMW_UTILS_STRCMP(ecdh_key_type[i].smw_key_type,
				      smw_key_type))
			ecc_family = ecdh_key_type[i].ecc_family;
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

	if (SMW_UTILS_STRCMP(smw_key_type, "DH"))
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

	if (SMW_UTILS_STRCMP(smw_key_type, "RSA"))
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

	if (!SMW_UTILS_STRNCMP(smw_key_type, "HMAC", SMW_UTILS_STRLEN("HMAC")))
		psa_key_type = PSA_KEY_TYPE_HMAC;

	return psa_key_type;
}

psa_key_type_t get_cipher_psa_key_type(smw_key_type_t smw_key_type)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (!SMW_UTILS_STRCMP(cipher_key_type[i].smw_key_type,
				      smw_key_type)) {
			SMW_DBG_PRINTF(DEBUG, "Key type name: %s\n",
				       cipher_key_type[i].smw_key_type);
			return cipher_key_type[i].psa_key_type;
		}
	}

	return PSA_KEY_TYPE_NONE;
}

static smw_key_type_t get_smw_key_type(const psa_key_attributes_t *attributes,
				       unsigned int security_size)
{
	unsigned int i;

	psa_key_type_t psa_key_type;
	psa_algorithm_t alg;
	psa_ecc_family_t ecc_family;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attributes)
		return NULL;

	psa_key_type = psa_get_key_type(attributes);
	alg = psa_get_key_algorithm(attributes);

	if (PSA_KEY_TYPE_IS_DH(psa_key_type))
		return "DH";

	if (PSA_KEY_TYPE_IS_RSA(psa_key_type))
		return "RSA";

	if (psa_key_type == PSA_KEY_TYPE_DES) {
		if (security_size == 56)
			return "DES";
		else if (security_size == 112 || security_size == 168)
			return "DES3";
		else
			return NULL;
	}

	if (psa_key_type == PSA_KEY_TYPE_HMAC)
		return get_hmac_smw_key_type(PSA_ALG_GET_HASH(alg));

	if (PSA_KEY_TYPE_IS_ECC(psa_key_type)) {
		ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_key_type);

		return get_ecc_smw_key_type(ecc_family, alg);
	}

	for (i = 0; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (cipher_key_type[i].psa_key_type == psa_key_type) {
			SMW_DBG_PRINTF(DEBUG, "Key type: %s\n",
				       cipher_key_type[i].smw_key_type);
			return cipher_key_type[i].smw_key_type;
		}
	}

	return NULL;
}

static psa_status_t get_psa_key_type(psa_key_type_t *psa_key_type,
				     const smw_key_type_t smw_key_type,
				     const char *privacy)
{
	psa_status_t status = PSA_ERROR_DATA_INVALID;
	bool is_keypair = false;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (privacy && smw_key_type) {
		if (!SMW_UTILS_STRCMP(privacy, "KEYPAIR"))
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
		if (*psa_key_type != PSA_KEY_TYPE_NONE)
			status = PSA_SUCCESS;
	}

	return status;
}

static void get_hash_name(psa_algorithm_t hash, const char **hash_str)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(key_hash); i++) {
		if (hash == key_hash[i].psa_hash) {
			*hash_str = key_hash[i].hash_str;
			SMW_DBG_PRINTF(DEBUG, "Key hash: %s (0x%.8x)\n",
				       *hash_str, hash);
			break;
		}
	}
}

static psa_algorithm_t get_hash_alg_from_name(const char *hash_str)
{
	psa_algorithm_t alg = PSA_ALG_NONE;
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(key_hash); i++) {
		if (!SMW_UTILS_STRCMP(key_hash[i].hash_str, hash_str)) {
			alg = key_hash[i].psa_hash;
			SMW_DBG_PRINTF(DEBUG, "Key hash: %s (0x%.8x)\n",
				       hash_str, alg);
			break;
		}
	}

	return alg;
}

static void get_kdf_name(psa_algorithm_t kdf, const char **kdf_str)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	if (kdf == PSA_ALG_HKDF_BASE)
		*kdf_str = HKDF_STR;
	else if (kdf == PSA_ALG_TLS12_PRF_BASE)
		*kdf_str = TLS12_PRF_STR;
	else if (kdf == PSA_ALG_TLS12_PSK_TO_MS_BASE)
		*kdf_str = TLS12_PSK_TO_MS_STR;
	else if (kdf == PSA_ALG_PBKDF2_HMAC_BASE)
		*kdf_str = PBKDF2_HMAC_STR;
	else if (kdf == PSA_ALG_PBKDF2_AES_CMAC_PRF_128)
		*kdf_str = PBKDF2_AES_CMAC_PRF_128_STR;
}

static psa_algorithm_t get_kdf_alg_from_name(const char *kdf_str)
{
	psa_algorithm_t alg = PSA_ALG_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!SMW_UTILS_STRCMP(HKDF_STR, kdf_str))
		alg = PSA_ALG_HKDF_BASE;

	else if (!SMW_UTILS_STRCMP(TLS12_PRF_STR, kdf_str))
		alg = PSA_ALG_TLS12_PRF_BASE;

	else if (!SMW_UTILS_STRCMP(TLS12_PSK_TO_MS_STR, kdf_str))
		alg = PSA_ALG_TLS12_PSK_TO_MS_BASE;

	else if (!SMW_UTILS_STRCMP(PBKDF2_HMAC_STR, kdf_str))
		alg = PSA_ALG_PBKDF2_HMAC_BASE;

	else if (!SMW_UTILS_STRCMP(PBKDF2_AES_CMAC_PRF_128_STR, kdf_str))
		alg = PSA_ALG_PBKDF2_AES_CMAC_PRF_128;

	return alg;
}

static void get_aead_alg(psa_algorithm_t alg, const char **alg_str)
{
	if (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0) ==
	    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, 0))
		*alg_str = CCM_STR;
	else if (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0) ==
		 PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 0))
		*alg_str = GCM_STR;
	else if (PSA_ALG_AEAD_WITH_SHORTENED_TAG(alg, 0) ==
		 PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CHACHA20_POLY1305, 0))
		*alg_str = CHACHA20_POLY1305_STR;
}

static void get_mac_alg(psa_algorithm_t alg, const char **alg_str)
{
	alg = alg & ~(PSA_ALG_AEAD_TAG_LENGTH_MASK |
		      PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG);

	if (alg == PSA_ALG_CBC_MAC)
		*alg_str = CBC_MAC_STR;
	else if (alg == PSA_ALG_CMAC)
		*alg_str = CMAC_STR;
}

static void get_alg_name(psa_algorithm_t alg, const char **alg_str,
			 const char **hash_str, const char **kdf_str,
			 uint8_t *length, uint8_t *min_length)
{
	unsigned int i;
	uint8_t l;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*alg_str = NULL;
	*hash_str = NULL;
	*kdf_str = NULL;
	*length = 0;
	*min_length = 0;

	if (!alg)
		return;

	if (PSA_ALG_IS_KEY_AGREEMENT(alg)) {
		get_kdf_name(PSA_ALG_KEY_AGREEMENT_GET_KDF(alg), kdf_str);
		get_hash_name(PSA_ALG_GET_HASH(alg), hash_str);
		alg = PSA_ALG_KEY_AGREEMENT_GET_BASE(alg);
	}

	for (i = 0; i < ARRAY_SIZE(key_algorithm); i++) {
		if (alg == key_algorithm[i].psa_alg) {
			*alg_str = key_algorithm[i].alg_str;
			SMW_DBG_PRINTF(DEBUG, "Key algorithm: %s (0x%.8x)\n",
				       *alg_str, alg);
			break;
		}
	}

	if (!*alg_str) {
		if (PSA_ALG_IS_HMAC(alg))
			*alg_str = HMAC_STR;
		else if (PSA_ALG_IS_HKDF(alg))
			*alg_str = HKDF_STR;
		else if (PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg))
			*alg_str = RSA_PKCS1V15_STR;
		else if (PSA_ALG_IS_RSA_PSS_STANDARD_SALT(alg))
			*alg_str = RSA_PSS_STR;
		else if (PSA_ALG_IS_RSA_PSS_ANY_SALT(alg))
			*alg_str = RSA_PSS_ANY_SALT_STR;
		else if (PSA_ALG_IS_ECDSA(alg))
			*alg_str = ECDSA_STR;
		else if (PSA_ALG_IS_DETERMINISTIC_ECDSA(alg))
			*alg_str = DETERMINISTIC_ECDSA_STR;
		else if (PSA_ALG_IS_RSA_OAEP(alg))
			*alg_str = RSA_OAEP_STR;

		if (*alg_str)
			get_hash_name(PSA_ALG_GET_HASH(alg), hash_str);
	}

	if (PSA_ALG_IS_AEAD(alg)) {
		get_aead_alg(alg, alg_str);

		l = (alg & PSA_ALG_AEAD_TAG_LENGTH_MASK) >>
		    PSA_AEAD_TAG_LENGTH_OFFSET;

		if (alg & PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG)
			*min_length = l;
		else
			*length = l;
	} else if (PSA_ALG_IS_MAC(alg)) {
		get_mac_alg(alg, alg_str);

		l = (alg & PSA_ALG_MAC_TRUNCATION_MASK) >>
		    PSA_MAC_TRUNCATION_OFFSET;

		if (alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG)
			*min_length = l;
		else
			*length = l;
	}
}

static psa_status_t set_key_algo(psa_algorithm_t alg, unsigned char **tlv,
				 unsigned int *tlv_length)
{
	const char *alg_str = NULL;
	const char *hash_str = NULL;
	const char *kdf_str = NULL;
	unsigned int alg_len = 0;
	unsigned int hash_len = 0;
	unsigned int kdf_len = 0;
	uint8_t length = 0;
	uint8_t min_length = 0;
	unsigned char *p;
	unsigned char *kdf_tlv = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*tlv = NULL;
	*tlv_length = 0;

	if (!alg)
		return PSA_SUCCESS;

	get_alg_name(alg, &alg_str, &hash_str, &kdf_str, &length, &min_length);

	if (alg_str)
		alg_len = SMW_UTILS_STRLEN(alg_str);

	if (!alg_str || !alg_len)
		return PSA_ERROR_INVALID_ARGUMENT;

	if (hash_str)
		hash_len = SMW_UTILS_STRLEN(hash_str);

	if (kdf_str)
		kdf_len = SMW_UTILS_STRLEN(kdf_str);

	*tlv_length += alg_len + 1;

	if (hash_len)
		*tlv_length += SMW_TLV_ELEMENT_LENGTH(HASH_STR, hash_len + 1);

	if (kdf_len)
		*tlv_length += SMW_TLV_ELEMENT_LENGTH(KDF_STR, kdf_len + 1);

	if (length)
		*tlv_length +=
			SMW_TLV_ELEMENT_LENGTH(LENGTH_STR, sizeof(length));

	if (min_length)
		*tlv_length += SMW_TLV_ELEMENT_LENGTH(MIN_LENGTH_STR,
						      sizeof(min_length));

	*tlv = SMW_UTILS_MALLOC(*tlv_length);
	if (!*tlv)
		return PSA_ERROR_INSUFFICIENT_MEMORY;

	p = *tlv;
	SMW_UTILS_MEMCPY(p, alg_str, alg_len + 1);
	p += alg_len + 1;

	if (kdf_len) {
		kdf_tlv = p;
		smw_tlv_set_string(&p, KDF_STR, kdf_str);
	}

	if (hash_len)
		smw_tlv_set_string(&p, HASH_STR, hash_str);

	if (length)
		smw_tlv_set_numeral(&p, LENGTH_STR, length);

	if (min_length)
		smw_tlv_set_numeral(&p, MIN_LENGTH_STR, min_length);

	if (kdf_len)
		smw_tlv_set_length(kdf_tlv, p);

	return PSA_SUCCESS;
}

static unsigned int get_usage_tlv_length(psa_key_usage_t usage_flags,
					 unsigned int algo_tlv_length)
{
	unsigned int usage_tlv_length = 0;
	unsigned int usage_v_length = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(key_usage); i++) {
		if (usage_flags & key_usage[i].psa_usage) {
			usage_v_length =
				SMW_UTILS_STRLEN(key_usage[i].usage_str) + 1;

			if (key_usage[i].restricted)
				usage_v_length += algo_tlv_length;

			usage_tlv_length +=
				SMW_TLV_ELEMENT_LENGTH(USAGE_STR,
						       usage_v_length);
		}
	}

	return usage_tlv_length;
}

static psa_key_usage_t get_usage_from_smw(const char *usage)
{
	psa_key_usage_t psa_usage = 0;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(key_usage) && !psa_usage; i++) {
		if (!SMW_UTILS_STRCMP(usage, key_usage[i].usage_str)) {
			psa_usage = key_usage[i].psa_usage;
			break;
		}
	}

	return psa_usage;
}

static void set_aead_tag_length(psa_algorithm_t *psa_algo, uint8_t length,
				uint8_t min_length)
{
	if (min_length)
		*psa_algo =
			PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(*psa_algo,
								   min_length);
	else if (length)
		*psa_algo = PSA_ALG_AEAD_WITH_SHORTENED_TAG(*psa_algo, length);
}

static void set_mac_length(psa_algorithm_t *psa_algo, uint8_t length,
			   uint8_t min_length)
{
	if (min_length)
		*psa_algo =
			PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(*psa_algo, min_length);
	else if (length)
		*psa_algo = PSA_ALG_TRUNCATED_MAC(*psa_algo, length);
}

static psa_status_t get_algo_from_smw(psa_algorithm_t *psa_algo,
				      const char *algo,
				      unsigned int algo_length)
{
	psa_status_t psa_status = PSA_ERROR_DATA_INVALID;
	int status = SMW_STATUS_KEY_POLICY_ERROR;
	const unsigned char *p = (const unsigned char *)algo;
	const unsigned char *p_end = p + algo_length;
	char *tlv_type = NULL;
	unsigned char *tlv_value = NULL;
	unsigned int tlv_length = 0;
	const char *alg_str = NULL;
	psa_algorithm_t alg_hash = PSA_ALG_NONE;
	psa_algorithm_t alg_kdf = PSA_ALG_NONE;
	uint8_t length = 0;
	uint8_t min_length = 0;
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*psa_algo = PSA_ALG_NONE;

	status = smw_tlv_read_element(&p, p_end, (unsigned char **)&tlv_type,
				      &tlv_value, &tlv_length);
	if (status != SMW_STATUS_OK) {
		SMW_DBG_PRINTF(ERROR, "%s Parsing policy failed\n", __func__);
		goto end;
	}

	if (SMW_UTILS_STRCMP(tlv_type, ALGO_STR)) {
		SMW_DBG_PRINTF(ERROR, "%s Parsing policy (algo) failed\n",
			       __func__);
		goto end;
	}

	alg_str = (const char *)tlv_value;

	p = tlv_value + SMW_UTILS_STRLEN((char *)tlv_value) + 1;

	while (p < p_end) {
		status = smw_tlv_read_element(&p, p_end,
					      (unsigned char **)&tlv_type,
					      &tlv_value, &tlv_length);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s Parsing policy failed\n",
				       __func__);
			goto end;
		}

		if (!SMW_UTILS_STRCMP(tlv_type, HASH_STR)) {
			alg_hash =
				get_hash_alg_from_name((const char *)tlv_value);
		} else if (!SMW_UTILS_STRCMP(tlv_type, KDF_STR)) {
			alg_kdf =
				get_kdf_alg_from_name((const char *)tlv_value);
		} else if (!SMW_UTILS_STRCMP(tlv_type, LENGTH_STR)) {
			if (tlv_length > sizeof(length)) {
				psa_status = PSA_ERROR_DATA_INVALID;
				goto end;
			}

			length = smw_tlv_convert_numeral(tlv_length, tlv_value);
		} else if (!SMW_UTILS_STRCMP(tlv_type, MIN_LENGTH_STR)) {
			if (tlv_length > sizeof(min_length)) {
				psa_status = PSA_ERROR_DATA_INVALID;
				goto end;
			}

			min_length =
				smw_tlv_convert_numeral(tlv_length, tlv_value);
		} else {
			SMW_DBG_PRINTF(ERROR, "%s Unknown type %s\n", __func__,
				       tlv_type);
			goto end;
		}
	}

	for (; i < ARRAY_SIZE(key_algorithm); i++) {
		if (!SMW_UTILS_STRCMP(key_algorithm[i].alg_str, alg_str)) {
			*psa_algo = key_algorithm[i].psa_alg;
			break;
		}
	}

	if (*psa_algo == PSA_ALG_NONE) {
		if (!SMW_UTILS_STRCMP(HMAC_STR, alg_str)) {
			*psa_algo = PSA_ALG_HMAC_BASE;
		} else if (!SMW_UTILS_STRCMP(HKDF_STR, alg_str)) {
			*psa_algo = PSA_ALG_HKDF_BASE;
		} else if (!SMW_UTILS_STRCMP(RSA_PKCS1V15_STR, alg_str)) {
			*psa_algo = PSA_ALG_RSA_PKCS1V15_SIGN_BASE;
		} else if (!SMW_UTILS_STRCMP(RSA_PSS_STR, alg_str)) {
			*psa_algo = PSA_ALG_RSA_PSS_BASE;
		} else if (!SMW_UTILS_STRCMP(RSA_PSS_ANY_SALT_STR, alg_str)) {
			*psa_algo = PSA_ALG_RSA_PSS_ANY_SALT_BASE;
		} else if (!SMW_UTILS_STRCMP(ECDSA_STR, alg_str)) {
			*psa_algo = PSA_ALG_ECDSA_BASE;
		} else if (!SMW_UTILS_STRCMP(DETERMINISTIC_ECDSA_STR,
					     alg_str)) {
			*psa_algo = PSA_ALG_DETERMINISTIC_ECDSA_BASE;
		} else if (!SMW_UTILS_STRCMP(RSA_OAEP_STR, alg_str)) {
			*psa_algo = PSA_ALG_RSA_OAEP_BASE;
		} else {
			SMW_DBG_PRINTF(ERROR, "%s Unknown algorithm %s\n",
				       __func__, alg_str);
			goto end;
		}

		if (alg_hash != PSA_ALG_NONE)
			*psa_algo |= alg_hash;
	}

	SMW_DBG_PRINTF(DEBUG, "Key main algorithm: %s (0x%.8x)\n", alg_str,
		       *psa_algo);

	if (PSA_ALG_IS_HASH(*psa_algo) && alg_hash != PSA_ALG_NONE)
		*psa_algo |= alg_hash;
	else if (PSA_ALG_IS_KEY_AGREEMENT(*psa_algo))
		*psa_algo |= alg_kdf;
	else if (PSA_ALG_IS_AEAD(*psa_algo))
		set_aead_tag_length(psa_algo, length, min_length);
	else if (PSA_ALG_IS_MAC(*psa_algo))
		set_mac_length(psa_algo, length, min_length);

	psa_status = PSA_SUCCESS;

end:
	return psa_status;
}

static psa_status_t
get_psa_key_persistence(psa_key_persistence_t *psa_persistence,
			smw_keymgr_persistence_t persistence)
{
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; persistence && i < ARRAY_SIZE(key_persistences); i++) {
		if (!SMW_UTILS_STRCMP(key_persistences[i].str, persistence)) {
			*psa_persistence = key_persistences[i].persistence;
			return PSA_SUCCESS;
		}
	}

	return PSA_ERROR_DATA_INVALID;
}

static psa_status_t
get_smw_key_persistence(smw_keymgr_persistence_t *smw_persistence,
			psa_key_lifetime_t lifetime)
{
	unsigned int i = 0;
	psa_key_persistence_t persistence =
		PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime);

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(key_persistences); i++) {
		if (key_persistences[i].persistence == persistence) {
			*smw_persistence = key_persistences[i].str;
			return PSA_SUCCESS;
		}
	}

	return PSA_ERROR_DATA_INVALID;
}

static psa_status_t
set_key_attributes_list(const psa_key_attributes_t *attributes,
			unsigned char **key_attributes_list,
			unsigned int *key_attributes_list_length)
{
	psa_status_t psa_status = PSA_ERROR_INVALID_ARGUMENT;
	unsigned char *p = NULL;
	unsigned int i = 0;
	psa_key_usage_t usage_flags = 0;
	psa_key_lifetime_t lifetime = 0;
	unsigned char *policy_tlv = NULL;
	unsigned char *usage_tlv = NULL;
	unsigned char *algo_v = NULL;
	unsigned int algo_v_length = 0;
	unsigned int algo_tlv_length = 0;
	unsigned int usage_tlv_length = 0;
	unsigned int storage_id = 0;
	smw_keymgr_persistence_t key_persistence = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*key_attributes_list = NULL;
	*key_attributes_list_length = 0;

	if (!attributes)
		return psa_status;

	usage_flags = psa_get_key_usage_flags(attributes);

	psa_status = set_key_algo(psa_get_key_algorithm(attributes), &algo_v,
				  &algo_v_length);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	lifetime = psa_get_key_lifetime(attributes);
	psa_status = get_smw_key_persistence(&key_persistence, lifetime);
	if (psa_status != PSA_SUCCESS)
		return psa_status;

	if (algo_v_length)
		algo_tlv_length =
			SMW_TLV_ELEMENT_LENGTH(ALGO_STR, algo_v_length);

	usage_tlv_length = get_usage_tlv_length(usage_flags, algo_tlv_length);

	*key_attributes_list_length =
		SMW_TLV_ELEMENT_LENGTH(POLICY_STR, usage_tlv_length);

	if (!PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
		*key_attributes_list_length +=
			SMW_TLV_ELEMENT_LENGTH(key_persistence, 0);

		*key_attributes_list_length +=
			SMW_TLV_ELEMENT_LENGTH(FLUSH_KEY_STR, 0);
	}

	storage_id = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);
	*key_attributes_list_length +=
		SMW_TLV_ELEMENT_LENGTH(STORAGE_ID_STR,
				       smw_tlv_numeral_length(storage_id));

	*key_attributes_list = SMW_UTILS_MALLOC(*key_attributes_list_length);
	if (!*key_attributes_list) {
		psa_status = PSA_ERROR_INSUFFICIENT_MEMORY;
		goto end;
	}

	p = *key_attributes_list;

	if (!PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
		smw_tlv_set_boolean(&p, key_persistence);

		smw_tlv_set_boolean(&p, FLUSH_KEY_STR);
	}

	smw_tlv_set_numeral(&p, STORAGE_ID_STR, storage_id);

	policy_tlv = p;
	smw_tlv_set_type(&p, POLICY_STR);

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (usage_flags & key_usage[i].psa_usage) {
			usage_tlv = p;
			smw_tlv_set_string(&p, USAGE_STR,
					   key_usage[i].usage_str);

			if (key_usage[i].restricted && algo_v && algo_v_length)
				smw_tlv_set_element(&p, ALGO_STR, algo_v,
						    algo_v_length);

			smw_tlv_set_length(usage_tlv, p);
		}
	}

	smw_tlv_set_length(policy_tlv, p);

	SMW_DBG_ASSERT(*key_attributes_list_length ==
		       (unsigned int)(p - *key_attributes_list));

end:
	if (psa_status != PSA_SUCCESS) {
		if (*key_attributes_list)
			SMW_UTILS_FREE(*key_attributes_list);
	}

	if (algo_v)
		SMW_UTILS_FREE(algo_v);

	return psa_status;
}

static psa_status_t read_key_policy_list(psa_key_attributes_t *attributes,
					 const unsigned char *policy,
					 unsigned int policy_length)
{
	int psa_status = PSA_ERROR_DATA_INVALID;
	int status = SMW_STATUS_KEY_POLICY_ERROR;
	const unsigned char *p = policy;
	const unsigned char *p_end = policy + policy_length;
	unsigned int usage_str_len = 0;
	char *tlv_type = NULL;
	char *tlv_value = NULL;
	unsigned int tlv_length = 0;
	psa_key_usage_t usage_flags = 0;
	psa_algorithm_t perm_algo = PSA_ALG_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!policy || !policy_length)
		goto end;

	status =
		smw_tlv_read_element(&p, p_end, (unsigned char **)&tlv_type,
				     (unsigned char **)&tlv_value, &tlv_length);
	if (status != SMW_STATUS_OK)
		goto end;

	/* Check first that policy is starting with POLICY_STR */
	if (SMW_UTILS_STRCMP(tlv_type, POLICY_STR))
		goto end;

	/*
	 * Parse all elements of the list, each element must start with
	 * USAGE_STR
	 */
	p = (const unsigned char *)tlv_value;
	while (p < p_end) {
		status = smw_tlv_read_element(&p, p_end,
					      (unsigned char **)&tlv_type,
					      (unsigned char **)&tlv_value,
					      &tlv_length);
		if (status != SMW_STATUS_OK) {
			SMW_DBG_PRINTF(ERROR, "%s Parsing policy failed\n",
				       __func__);
			goto end;
		}

		if (SMW_UTILS_STRCMP(tlv_type, USAGE_STR)) {
			SMW_DBG_PRINTF(ERROR, "%s Expected type %s got %s\n",
				       __func__, USAGE_STR, tlv_type);
			goto end;
		}

		usage_flags |= get_usage_from_smw(tlv_value);
		usage_str_len = SMW_UTILS_STRLEN(tlv_value) + 1;
		if (usage_str_len < tlv_length && perm_algo == PSA_ALG_NONE) {
			psa_status =
				get_algo_from_smw(&perm_algo,
						  tlv_value + usage_str_len,
						  tlv_length - usage_str_len);
			if (psa_status != PSA_SUCCESS)
				goto end;
		}
	}

	psa_set_key_usage_flags(attributes, usage_flags);
	psa_set_key_algorithm(attributes, perm_algo);

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
	psa_status_t psa_status;
	enum smw_status_code status;
	struct smw_keypair_rsa *keypair_rsa;
	uint8_t *modulus = NULL;
	uint8_t *public_data = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!data || !data_size || !data_length || !args ||
	    !args->key_descriptor || !args->key_descriptor->buffer)
		return PSA_ERROR_INVALID_ARGUMENT;

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
	enum smw_status_code status;
	struct smw_keypair_gen *keypair_gen;

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
	enum smw_status_code status;
	struct smw_keypair_gen *keypair_gen;

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
	enum smw_status_code status;
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

	if (!SMW_UTILS_STRCMP(key_descriptor.type_name, "RSA")) {
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
	enum smw_status_code status;
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
	psa_status_t psa_status;
	struct smw_generate_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	if (!attributes || !key)
		return PSA_ERROR_INVALID_ARGUMENT;

	key_descriptor.id = psa_get_key_id(attributes);
	key_descriptor.security_size = psa_get_key_bits(attributes);

	key_descriptor.type_name =
		get_smw_key_type(attributes, key_descriptor.security_size);
	if (!key_descriptor.type_name)
		return PSA_ERROR_NOT_SUPPORTED;

	psa_status =
		set_key_attributes_list(attributes, &args.key_attributes_list,
					&args.key_attributes_list_length);
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

	if (args.key_attributes_list)
		SMW_UTILS_FREE(args.key_attributes_list);

	return psa_status;
}

__export psa_status_t psa_get_key_attributes(psa_key_id_t key,
					     psa_key_attributes_t *attributes)
{
	psa_status_t psa_status = PSA_ERROR_BAD_STATE;
	enum smw_status_code status = SMW_STATUS_OPERATION_NOT_SUPPORTED;
	struct smw_get_key_attributes_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	psa_key_persistence_t key_persistence = PSA_KEY_PERSISTENCE_VOLATILE;
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
				      args.key_privacy);
	if (psa_status != PSA_SUCCESS)
		goto exit;

	psa_set_key_type(attributes, key_type);

	psa_set_key_bits(attributes, args.key_descriptor->security_size);

	psa_status =
		get_psa_key_persistence(&key_persistence, args.persistence);
	if (psa_status != PSA_SUCCESS)
		goto exit;

	attributes->lifetime =
		PSA_KEY_LIFETIME_GET_LIFETIME(key_persistence, args.storage);

	psa_status = read_key_policy_list(attributes, args.policy_list,
					  args.policy_list_length);

exit:
	if (args.policy_list)
		free(args.policy_list);

	if (args.lifecycle_list)
		free(args.lifecycle_list);

	if (psa_status != PSA_SUCCESS)
		psa_reset_key_attributes(attributes);

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
	unsigned int security_size = 0;
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

	key_descriptor.security_size = security_size;

	key_descriptor.type_name =
		get_smw_key_type(attributes, key_descriptor.security_size);
	if (!key_descriptor.type_name)
		return PSA_ERROR_NOT_SUPPORTED;

	psa_status =
		set_key_attributes_list(attributes, &args.key_attributes_list,
					&args.key_attributes_list_length);
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

	if (args.key_attributes_list)
		SMW_UTILS_FREE(args.key_attributes_list);

	return psa_status;
}

__export psa_status_t
psa_key_derivation_abort(psa_key_derivation_operation_t *operation)
{
	(void)operation;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_input_bytes(psa_key_derivation_operation_t *operation,
			       psa_key_derivation_step_t step,
			       const uint8_t *data, size_t data_length)
{
	(void)operation;
	(void)step;
	(void)data;
	(void)data_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	(void)operation;
	(void)step;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_key_agreement(psa_key_derivation_operation_t *operation,
				 psa_key_derivation_step_t step,
				 psa_key_id_t private_key,
				 const uint8_t *peer_key,
				 size_t peer_key_length)
{
	(void)operation;
	(void)step;
	(void)private_key;
	(void)peer_key;
	(void)peer_key_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
psa_key_derivation_output_bytes(psa_key_derivation_operation_t *operation,
				uint8_t *output, size_t output_length)
{
	(void)operation;
	(void)output;
	(void)output_length;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t
/* Without this comment clang-format does not meet the checkpatch requirement. */
psa_key_derivation_output_key(const psa_key_attributes_t *attributes,
			      psa_key_derivation_operation_t *operation,
			      psa_key_id_t *key)
{
	(void)attributes;
	(void)operation;
	(void)key;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
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
	(void)operation;
	(void)alg;

	SMW_DBG_TRACE_FUNCTION_CALL;

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
