// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <psa/crypto.h>

#include "types.h"
#include "util.h"
#include "util_key.h"

#include "key.h"

#define BASE64_STR "BASE64"

#define EXPORT_STR	   "export"
#define COPY_STR	   "copy"
#define ENCRYPT_STR	   "encrypt"
#define DECRYPT_STR	   "decrypt"
#define SIGN_MESSAGE_STR   "sign_message"
#define VERIFY_MESSAGE_STR "verify_message"
#define SIGN_HASH_STR	   "sign_hash"
#define VERIFY_HASH_STR	   "verify_hash"
#define DERIVE_STR	   "derive"

#define HASH_STR       "HASH"
#define KDF_STR	       "KDF"
#define LENGTH_STR     "LENGTH"
#define MIN_LENGTH_STR "MIN_LENGTH"

#define DH_STR	    "DH"
#define RSA_STR	    "RSA"
#define KEYPAIR_STR "KEYPAIR"

#define ANY_STR			    "ANY"
#define ALL_AEAD_STR		    "ALL_AEAD"
#define ALL_CIPHER_STR		    "ALL_CIPHER"
#define HMAC_STR		    "HMAC"
#define CBC_MAC_STR		    "CBC_MAC"
#define CMAC_STR		    "CMAC"
#define STREAM_CIPHER_STR	    "STREAM_CIPHER"
#define CTR_STR			    "CTR"
#define CFB_STR			    "CFB"
#define OFB_STR			    "OFB"
#define XTS_STR			    "XTS"
#define ECB_NO_PADDING_STR	    "ECB_NO_PADDING"
#define CBC_NO_PADDING_STR	    "CBC_NO_PADDING"
#define CBC_PKCS7_STR		    "CBC_PKCS7"
#define CCM_STR			    "CCM"
#define GCM_STR			    "GCM"
#define CHACHA20_POLY1305_STR	    "CHACHA20_POLY1305"
#define HKDF_STR		    "HKDF"
#define TLS12_PRF_STR		    "TLS12_PRF"
#define TLS12_PSK_TO_MS_STR	    "TLS12_PSK_TO_MS"
#define PBKDF2_HMAC_STR		    "PBKDF2_HMAC"
#define PBKDF2_AES_CMAC_PRF_128_STR "PBKDF2_AES_CMAC_PRF_128"
#define RSA_PKCS1V15_STR	    "RSA_PKCS1V15"
#define RSA_PSS_STR		    "RSA_PSS"
#define RSA_PSS_ANY_SALT_STR	    "RSA_PSS_ANY_SALT"
#define ECDSA_STR		    "ECDSA"
#define DETERMINISTIC_ECDSA_STR	    "DETERMINISTIC_ECDSA"
#define PURE_EDDSA_STR		    "PURE_EDDSA"
#define ED25519PH_STR		    "ED25519PH"
#define ED448PH_STR		    "ED448PH"
#define RSA_PKCS1V15_CRYPT_STR	    "RSA_PKCS1V15_CRYPT"
#define RSA_OAEP_STR		    "RSA_OAEP"
#define ECDH_STR		    "ECDH"
#define FFDH_STR		    "FFDH"
#define MD2_STR			    "MD2"
#define MD4_STR			    "MD4"
#define MD5_STR			    "MD5"
#define RIPEMD160_STR		    "RIPEMD160"
#define SHA_1_STR		    "SHA1"
#define SHA_224_STR		    "SHA224"
#define SHA_256_STR		    "SHA256"
#define SHA_384_STR		    "SHA384"
#define SHA_512_STR		    "SHA512"
#define SHA_512_224_STR		    "SHA512_224"
#define SHA_512_256_STR		    "SHA512_256"
#define SHA3_224_STR		    "SHA3_224"
#define SHA3_256_STR		    "SHA3_256"
#define SHA3_384_STR		    "SHA3_384"
#define SHA3_512_STR		    "SHA3_512"
#define SHAKE256_512_STR	    "SHAKE256_512"
#define SM3_STR			    "SM3"

#define KEY_TYPE(_name, _psa)                                                  \
	{                                                                      \
		.key_type_name = _name, .psa_key_type = PSA_KEY_TYPE_##_psa,   \
	}

/**
 * struct - Key type
 * @key_type_name: Key type name.
 * @psa_key_type: PSA key type.
 */
static const struct cipher_key_type {
	const char *key_type_name;
	psa_key_type_t psa_key_type;
} cipher_key_type[] = { KEY_TYPE("AES", AES), KEY_TYPE("DES", DES),
			KEY_TYPE("DES3", DES), KEY_TYPE("SM4", SM4) };

#define ECC_KEY_TYPE(_name, _family)                                           \
	{                                                                      \
		.key_type_name = _name, .ecc_family = PSA_ECC_FAMILY_##_family \
	}

/**
 * struct - ECC key type
 * @key_type_name: SMW HMAC key type name.
 * @ecc_family: Elliptic curve family.
 */
struct ecc_key_type {
	const char *key_type_name;
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

#define KEY_USAGE(_name, _restricted)                                          \
	{                                                                      \
		.usage_str = _name##_STR, .psa_usage = PSA_KEY_USAGE_##_name,  \
		.restricted = _restricted                                      \
	}

/**
 * struct - Key usage
 * @usage_str: Usage name in test definition file.
 * @psa_usage: PSA usage id.
 * @restricted: Is usage restricted to an algorithm.
 */
struct key_usage_info {
	const char *usage_str;
	psa_key_usage_t psa_usage;
	bool restricted;
};

static const struct key_usage_info key_usage[] = {
	KEY_USAGE(EXPORT, false),      KEY_USAGE(COPY, false),
	KEY_USAGE(ENCRYPT, true),      KEY_USAGE(DECRYPT, true),
	KEY_USAGE(SIGN_MESSAGE, true), KEY_USAGE(VERIFY_MESSAGE, true),
	KEY_USAGE(SIGN_HASH, true),    KEY_USAGE(VERIFY_HASH, true),
	KEY_USAGE(DERIVE, true)
};

static const struct {
	const char *persistence_str;
	psa_key_persistence_t psa_persistence;
} key_persistence[] = {
	{ "TRANSIENT", PSA_KEY_PERSISTENCE_VOLATILE },
	{ "PERSISTENT", PSA_KEY_PERSISTENCE_DEFAULT },
	{ "PERMANENT", PSA_KEY_PERSISTENCE_READ_ONLY },
};

static psa_key_type_t get_ecc_psa_key_type(const char *key_type_name,
					   const char *privacy_name)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	bool is_keypair = false;
	psa_ecc_family_t ecc_family = 0;
	unsigned int i = 0;

	if (!privacy_name)
		return psa_key_type;

	for (; !ecc_family && i < ARRAY_SIZE(ecdsa_key_type); i++) {
		if (!strcmp(ecdsa_key_type[i].key_type_name, key_type_name))
			ecc_family = ecdsa_key_type[i].ecc_family;
	}

	for (i = 0; !ecc_family && i < ARRAY_SIZE(ecdh_key_type); i++) {
		if (!strcmp(ecdh_key_type[i].key_type_name, key_type_name))
			ecc_family = ecdh_key_type[i].ecc_family;
	}

	if (!ecc_family)
		return psa_key_type;

	if (!strcmp(privacy_name, KEYPAIR_STR))
		is_keypair = true;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family);
	else
		psa_key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(ecc_family);

	return psa_key_type;
}

static psa_key_type_t get_dh_psa_key_type(const char *key_type_name,
					  const char *privacy_name)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	bool is_keypair = false;

	if (strcmp(key_type_name, DH_STR) || !privacy_name)
		return psa_key_type;

	if (!strcmp(privacy_name, KEYPAIR_STR))
		is_keypair = true;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
	else
		psa_key_type =
			PSA_KEY_TYPE_DH_PUBLIC_KEY(PSA_DH_FAMILY_RFC7919);

	return psa_key_type;
}

static psa_key_type_t get_rsa_psa_key_type(const char *key_type_name,
					   const char *privacy_name)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	bool is_keypair = false;

	if (strcmp(key_type_name, RSA_STR) || !privacy_name)
		return psa_key_type;

	if (!strcmp(privacy_name, KEYPAIR_STR))
		is_keypair = true;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_RSA_KEY_PAIR;
	else
		psa_key_type = PSA_KEY_TYPE_RSA_PUBLIC_KEY;

	return psa_key_type;
}

static psa_key_type_t get_hmac_psa_key_type(const char *key_type_name)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;

	if (!strncmp(key_type_name, HMAC_STR, strlen(HMAC_STR)))
		psa_key_type = PSA_KEY_TYPE_HMAC;

	return psa_key_type;
}

psa_key_type_t get_cipher_psa_key_type(const char *key_type_name)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (!strcmp(cipher_key_type[i].key_type_name, key_type_name))
			return cipher_key_type[i].psa_key_type;
	}

	return PSA_KEY_TYPE_NONE;
}

static int get_psa_key_type(psa_key_type_t *psa_key_type,
			    const char *key_type_name, const char *privacy_name)
{
	int ret = ERR_CODE(BAD_PARAM_TYPE);

	if (!psa_key_type)
		return ERR_CODE(BAD_ARGS);

	if (!key_type_name)
		return ret;

	*psa_key_type = get_dh_psa_key_type(key_type_name, privacy_name);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type =
			get_rsa_psa_key_type(key_type_name, privacy_name);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type =
			get_ecc_psa_key_type(key_type_name, privacy_name);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type = get_hmac_psa_key_type(key_type_name);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type = get_cipher_psa_key_type(key_type_name);
	if (*psa_key_type != PSA_KEY_TYPE_NONE)
		ret = ERR_CODE(PASSED);

	return ret;
}

static const struct key_usage_info *get_usage_info(const char *value)
{
	unsigned int i = 0;

	if (!value)
		return NULL;

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (!strcmp(key_usage[i].usage_str, value))
			return &key_usage[i];
	}

	return NULL;
}

static bool convert_hash(const char *value, psa_algorithm_t *hash)
{
	unsigned int i = 0;

	*hash = 0;

	if (!value)
		return false;

	for (; i < ARRAY_SIZE(key_hash); i++) {
		if (!strcmp(key_hash[i].hash_str, value)) {
			*hash = key_hash[i].psa_hash;
			return true;
		}
	}

	return false;
}

static bool convert_kdf(const char *value, psa_algorithm_t hash,
			psa_algorithm_t *kdf)
{
	*kdf = 0;

	if (!value)
		return false;

	if (!strcmp(HKDF_STR, value))
		*kdf = PSA_ALG_HKDF(hash);
	else if (!strcmp(TLS12_PRF_STR, value))
		*kdf = PSA_ALG_TLS12_PRF(hash);
	else if (!strcmp(TLS12_PSK_TO_MS_STR, value))
		*kdf = PSA_ALG_TLS12_PSK_TO_MS(hash);
	else if (!strcmp(PBKDF2_HMAC_STR, value))
		*kdf = PSA_ALG_PBKDF2_HMAC(hash);
	else if (!strcmp(PBKDF2_AES_CMAC_PRF_128_STR, value))
		*kdf = PSA_ALG_PBKDF2_AES_CMAC_PRF_128;
	else
		return false;

	return true;
}

static void set_aead_length(psa_algorithm_t *alg, unsigned int length,
			    unsigned int min_length)
{
	if (length)
		*alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(*alg, length);

	if (min_length)
		*alg = PSA_ALG_AEAD_WITH_AT_LEAST_THIS_LENGTH_TAG(*alg,
								  min_length);
}

static void set_mac_length(psa_algorithm_t *alg, unsigned int length,
			   unsigned int min_length)
{
	if (length)
		*alg = PSA_ALG_TRUNCATED_MAC(*alg, length);

	if (min_length)
		*alg = PSA_ALG_AT_LEAST_THIS_LENGTH_MAC(*alg, min_length);
}

static int convert_algo(const char *alg_str, const char *hash, const char *kdf,
			unsigned int length, unsigned int min_length,
			psa_algorithm_t *alg)
{
	unsigned int i = 0;
	psa_algorithm_t psa_hash = 0;
	psa_algorithm_t psa_kdf = 0;

	*alg = PSA_ALG_NONE;

	if (!alg_str)
		goto end;

	for (; i < ARRAY_SIZE(key_algorithm); i++) {
		if (!strcmp(key_algorithm[i].alg_str, alg_str)) {
			*alg = key_algorithm[i].psa_alg;
			break;
		}
	}

	if (!*alg) {
		if (!convert_hash(hash, &psa_hash))
			goto end;

		if (!strcmp(HMAC_STR, alg_str))
			*alg = PSA_ALG_HMAC(psa_hash);
		else if (!strcmp(HKDF_STR, alg_str))
			*alg = PSA_ALG_HKDF(psa_hash);
		else if (!strcmp(RSA_PKCS1V15_STR, alg_str))
			*alg = PSA_ALG_RSA_PKCS1V15_SIGN(psa_hash);
		else if (!strcmp(RSA_PSS_STR, alg_str))
			*alg = PSA_ALG_RSA_PSS(psa_hash);
		else if (!strcmp(RSA_PSS_ANY_SALT_STR, alg_str))
			*alg = PSA_ALG_RSA_PSS_ANY_SALT(psa_hash);
		else if (!strcmp(ECDSA_STR, alg_str))
			*alg = PSA_ALG_ECDSA(psa_hash);
		else if (!strcmp(DETERMINISTIC_ECDSA_STR, alg_str))
			*alg = PSA_ALG_DETERMINISTIC_ECDSA(psa_hash);
		else if (!strcmp(RSA_OAEP_STR, alg_str))
			*alg = PSA_ALG_RSA_OAEP(psa_hash);
		else
			goto end;
	}

	if (PSA_ALG_IS_AEAD(*alg)) {
		if (length && min_length)
			goto end;

		set_aead_length(alg, length, min_length);
	} else if (PSA_ALG_IS_MAC(*alg)) {
		if (length && min_length)
			goto end;

		set_mac_length(alg, length, min_length);
	} else if (PSA_ALG_IS_KEY_AGREEMENT(*alg)) {
		if (!convert_hash(hash, &psa_hash))
			goto end;

		if (!convert_kdf(kdf, psa_hash, &psa_kdf))
			goto end;

		*alg = PSA_ALG_KEY_AGREEMENT(*alg, psa_kdf);
	}

	return ERR_CODE(PASSED);

end:
	return ERR_CODE(BAD_PARAM_TYPE);
}

static int set_param_str(const char **param, const char *value)
{
	if (!param)
		return ERR_CODE(BAD_ARGS);

	if (*param)
		return ERR_CODE(BAD_PARAM_TYPE);

	*param = value;

	return ERR_CODE(PASSED);
}

static int set_param_num(unsigned int *param, const char *value)
{
	long num = 0;

	if (!param)
		return ERR_CODE(BAD_ARGS);

	if (*param)
		return ERR_CODE(BAD_PARAM_TYPE);

	num = strtol(value, NULL, 10);
	if (num == LONG_MIN || num == LONG_MAX)
		return ERR_CODE(BAD_PARAM_TYPE);

	if (num < 0)
		return ERR_CODE(BAD_PARAM_TYPE);

	*param = (unsigned int)num;

	return ERR_CODE(PASSED);
}

static int read_key_usage_algo(psa_algorithm_t *alg, struct json_object *oalgo)
{
	int ret = ERR_CODE(BAD_ARGS);

	unsigned int i = 0;
	struct json_object *oname = NULL;
	struct json_object *oparam = NULL;
	size_t size = 0;
	static const char delim[2] = "=";
	int len = 0;
	char *buf = NULL;
	const char *param_name = NULL;
	const char *param_value = NULL;

	const char *alg_str = NULL;
	const char *hash_str = NULL;
	const char *kdf_str = NULL;
	unsigned int length = 0;
	unsigned int min_length = 0;

	if (!alg)
		return ret;

	*alg = PSA_ALG_NONE;

	/*
	 * First element of the algorithm array is the
	 * algorithm name
	 */
	oname = json_object_array_get_idx(oalgo, 0);
	alg_str = json_object_get_string(oname);

	size = json_object_array_length(oalgo);

	for (i = 1; i < size; i++) {
		oparam = json_object_array_get_idx(oalgo, i);

		len = json_object_get_string_len(oparam) + 1;
		if (len <= 0) {
			ret = ERR_CODE(FAILED);
			goto end;
		}

		buf = malloc(len);
		if (!buf) {
			DBG_PRINT_ALLOC_FAILURE();
			return ERR_CODE(INTERNAL_OUT_OF_MEMORY);
		}
		strcpy(buf, json_object_get_string(oparam));

		param_name = strtok(buf, delim);
		if (!param_name) {
			DBG_PRINT("Key Algo parameter \"%s\" not supported",
				  json_object_get_string(oparam));
			ret = ERR_CODE(FAILED);
			goto end;
		}

		if ((unsigned int)len <= strlen(delim) ||
		    strlen(param_name) >= len - strlen(delim)) {
			ret = ERR_CODE(BAD_PARAM_TYPE);
			goto end;
		}

		param_value = json_object_get_string(oparam) +
			      strlen(param_name) + strlen(delim);

		if (!strcmp(param_name, HASH_STR)) {
			ret = set_param_str(&hash_str, param_value);
			if (ret != ERR_CODE(PASSED))
				goto end;
		} else if (!strcmp(param_name, LENGTH_STR)) {
			ret = set_param_num(&length, param_value);
			if (ret != ERR_CODE(PASSED))
				goto end;
		} else if (!strcmp(param_name, MIN_LENGTH_STR)) {
			ret = set_param_num(&min_length, param_value);
			if (ret != ERR_CODE(PASSED))
				goto end;
		} else if (!strcmp(param_name, KDF_STR)) {
			ret = set_param_str(&kdf_str, param_value);
			if (ret != ERR_CODE(PASSED))
				goto end;
		} else {
			ret = ERR_CODE(BAD_PARAM_TYPE);
			goto end;
		}

		free(buf);
		buf = NULL;
	}

	ret = convert_algo(alg_str, hash_str, kdf_str, length, min_length, alg);

end:
	if (buf)
		free(buf);

	return ret;
}

static int get_psa_key_persistence(psa_key_persistence_t *psa_persistence,
				   const char *persistence_str)
{
	unsigned int i = 0;

	for (; persistence_str && i < ARRAY_SIZE(key_persistence); i++) {
		if (!strcmp(key_persistence[i].persistence_str,
			    persistence_str)) {
			*psa_persistence = key_persistence[i].psa_persistence;
			return ERR_CODE(PASSED);
		}
	}

	return ERR_CODE(VALUE_NOTFOUND);
}

static int key_read_lifetime(psa_key_lifetime_t *lifetime,
			     struct json_object *okey)
{
	int ret = ERR_CODE(BAD_ARGS);
	struct json_object *oattr_list = NULL;
	struct json_object *oattr = NULL;
	struct json_object *opersistence = NULL;
	size_t nb_attrs = 0;
	unsigned int i = 0;
	psa_key_persistence_t persistence = PSA_KEY_PERSISTENCE_VOLATILE;
	psa_key_location_t storage = PSA_KEY_LOCATION_LOCAL_STORAGE;
	const char *persistence_str = NULL;

	if (!okey || !lifetime) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = util_read_json_type(&oattr_list, ATTR_LIST_OBJ, t_array, okey);
	if (ret != ERR_CODE(PASSED)) {
		/* If JSON tag not found, return with no error */
		if (ret == ERR_CODE(VALUE_NOTFOUND))
			ret = ERR_CODE(PASSED);

		return ret;
	}

	nb_attrs = json_object_array_length(oattr_list);
	DBG_PRINT("Get nb array attr %d", nb_attrs);

	/* Check if this is an array of array or just one attribute */
	oattr = json_object_array_get_idx(oattr_list, 0);
	if (json_object_get_type(oattr) != json_type_array) {
		nb_attrs = 1;

		/* There is only one attribute to read */
		oattr = oattr_list;
	}

	for (; i < nb_attrs; i++) {
		if (nb_attrs > 1)
			oattr = json_object_array_get_idx(oattr_list, i);

		if (json_object_array_length(oattr) == 1) {
			opersistence = json_object_array_get_idx(oattr, 0);
			persistence_str = json_object_get_string(opersistence);
			ret = get_psa_key_persistence(&persistence,
						      persistence_str);
			if (ret == ERR_CODE(PASSED))
				break;
		}
	}

	*lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(persistence,
								   storage);

	return ret;
}

static int key_read_policy(psa_key_attributes_t *attributes,
			   struct json_object *okey)
{
	int ret = ERR_CODE(BAD_ARGS);
	struct json_object *obj = NULL;
	struct json_object_iter usage;
	const struct key_usage_info *usage_info = NULL;
	psa_key_usage_t usage_flags = 0;
	psa_algorithm_t algorithm = PSA_ALG_NONE;
	psa_algorithm_t alg = PSA_ALG_NONE;

	if (!okey || !attributes) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	/*
	 * Key policy is an JSON-C object where each item is a
	 * key usage. Each key usage is an array (empty or not) of
	 * permitted algorithm(s).
	 *
	 * Definition is as below:
	 * "policy" : {
	 *     "usage_1" : [],
	 *     "usage_2" : [
	 *         ["algo_1", "MIN_LENGTH=32"],
	 *         ["algo_2"]
	 *     ]
	 * }
	 */
	ret = util_read_json_type(&obj, POLICY_OBJ, t_object, okey);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!json_object_get_object(obj))
		return ERR_CODE(PASSED);

	/*
	 * First step is to build all usages definition attributes
	 */
	json_object_object_foreachC(obj, usage)
	{
		algorithm = 0;

		if (json_object_get_type(usage.val) != json_type_array) {
			DBG_PRINT("Key usage %s must be an array", usage.key);
			return ERR_CODE(FAILED);
		}

		if (!json_object_array_length(usage.val))
			continue;

		if (json_object_array_length(usage.val) != 1)
			return ERR_CODE(BAD_PARAM_TYPE);

		usage_info = get_usage_info(usage.key);
		if (!usage_info)
			return ERR_CODE(BAD_PARAM_TYPE);

		if (!usage_info->restricted &&
		    json_object_array_length(usage.val))
			return ERR_CODE(BAD_PARAM_TYPE);

		usage_flags |= usage_info->psa_usage;

		ret = read_key_usage_algo(&algorithm,
					  json_object_array_get_idx(usage.val,
								    0));
		if (ret != ERR_CODE(PASSED))
			return ret;

		if (alg && algorithm && algorithm != alg)
			return ERR_CODE(BAD_PARAM_TYPE);

		if (!alg && algorithm)
			alg = algorithm;
	}

	attributes->usage_flags = usage_flags;
	attributes->alg = alg;

	return ret;
}

/**
 * read_key() - Read the key buffer from json-c object
 * @key: Key buffer to return
 * @length: Length of the key
 * @format: Key format of json-c buffer
 * @okey: Key json-c object
 *
 * Function read the json-c key object if defined.
 * Function allocates the key buffer caller must free it.
 *
 * Return:
 * PASSED                   - Success
 * -FAILED                  - Function failure
 * -INTERNAL_OUT_OF_MEMORY  - Out of memory
 * -BAD_ARGS                - Bad function argument
 */
static int read_key(unsigned char **key, size_t *length, const char *format,
		    struct json_object *okey)
{
	int ret = ERR_CODE(INTERNAL);
	char *buf = NULL;
	unsigned int len = 0;
	unsigned int json_len = UINT_MAX;

	if (!key || !length)
		return ret;

	ret = util_read_json_buffer(&buf, &len, &json_len, okey);
	if (ret != ERR_CODE(PASSED)) {
		if (buf)
			free(buf);
		return ret;
	}

	/* If key buffer was already defined, overwrite it with the new definition. */
	if (*key)
		free(*key);

	*key = NULL;
	*length = 0;

	/* Either test definition specify:
	 * - length != 0 but no data
	 * - length = 0 but data
	 * - no length but data
	 * - length and data
	 */
	if (!buf || (format && !strcmp(format, BASE64_STR))) {
		*key = (unsigned char *)buf;
	} else {
		ret = util_string_to_hex(buf, key, &len);
		/*
		 * Buffer can be freed because a new one has been
		 * allocated to convert the string to hex
		 */
		free(buf);

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	if (json_len != UINT_MAX) {
		if (*key && json_len > len)
			return ERR_CODE(BAD_ARGS);

		*length = json_len;
	} else {
		*length = len;
	}

	return ret;
}

/**
 * keypair_read() - Read the public and private key definition
 * @key_test: Test keypair structure
 * @params: json-c object
 *
 * Read and set the public key buffer and private key buffer.
 * Key buffer is defined by a string.
 * The public and private data buffer are allocated by this function
 * but must be freed by caller if function succeed.
 *
 * Return:
 * PASSED                   - Success.
 * -INTERNAL_OUT_OF_MEMORY  - Memory allocation failed.
 * -BAD_ARGS                - One of the arguments is bad.
 * -FAILED                  - Error in definition file
 */
static int keypair_read(struct keypair_psa *key_test,
			struct json_object *params)
{
	int ret = ERR_CODE(PASSED);
	struct json_object *okey = NULL;
	const char *format_name = NULL;

	if (!params || !key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (json_object_object_get_ex(params, FORMAT_OBJ, &okey))
		format_name = json_object_get_string(okey);

	if (json_object_object_get_ex(params, KEY_DATA_OBJ, &okey)) {
		ret = read_key(&key_test->data, &key_test->data_length,
			       format_name, okey);

		if (ret != ERR_CODE(PASSED))
			return ret;
	}

	return ret;
}

static int read_descriptor(struct llist *keys, struct keypair_psa *key_test,
			   const char *key_name, struct llist *key_names)
{
	int ret = ERR_CODE(PASSED);
	struct key_data *data = NULL;
	const char *parent_key_name = NULL;
	const char *privacy_name = KEYPAIR_STR;
	const char *type_name = NULL;
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	unsigned int security_size = 0;
	psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_VOLATILE;
	psa_key_id_t id = PSA_KEY_ID_NULL;
	void *dummy = NULL;

	if (!key_test || !key_name) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	ret = util_list_find_node(keys, (uintptr_t)key_name, (void **)&data);
	if (ret != ERR_CODE(PASSED))
		return ret;

	if (!data)
		return ERR_CODE(KEY_NOTFOUND);

	if (data->identifier)
		key_test->attributes.id = data->identifier;

	if (!data->okey_params)
		return ERR_CODE(PASSED);

	ret = util_read_json_type(&parent_key_name, KEY_NAME_OBJ, t_string,
				  data->okey_params);

	if (ret == ERR_CODE(PASSED) && parent_key_name) {
		ret = util_list_find_node(key_names, (uintptr_t)parent_key_name,
					  &dummy);
		if (ret != ERR_CODE(PASSED))
			return ret;

		if (dummy) {
			DBG_PRINT("Error: nested key definition (%s, %s)",
				  parent_key_name, key_name);
			return ERR_CODE(BAD_ARGS);
		}

		/*
		 * Add a node in list key_names with id set to parent_key_name.
		 * No data is stored by the node. But data pointer must be different to NULL
		 * in order to detect later if the node is found in the list.
		 * Data pointer is not freed when the list is cleared
		 * because the method to free the data is set to NULL
		 * when list is initialized.
		 */
		ret = util_list_add_node(key_names, (uintptr_t)parent_key_name,
					 (void *)1);
		if (ret != ERR_CODE(PASSED))
			return ret;

		ret = read_descriptor(keys, key_test, parent_key_name,
				      key_names);
		if (ret != ERR_CODE(PASSED))
			return ret;
	} else if (ret != ERR_CODE(VALUE_NOTFOUND)) {
		return ret;
	} else if (!parent_key_name) {
		ret = ERR_CODE(VALUE_NOTFOUND);
	}

	/* Read 'privacy' parameter if defined */
	ret = util_read_json_type(&privacy_name, PRIVACY_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'type' parameter if defined */
	ret = util_read_json_type(&type_name, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (type_name) {
		ret = get_psa_key_type(&psa_key_type, type_name, privacy_name);
		if (ret != ERR_CODE(PASSED))
			return ret;

		key_test->attributes.type = psa_key_type;
	}

	/* Read 'security_size' parameter if defined */
	ret = util_read_json_type(&security_size, SEC_SIZE_OBJ, t_int,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (ret == ERR_CODE(PASSED))
		key_test->attributes.bits = security_size;

	ret = key_read_lifetime(&lifetime, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (ret == ERR_CODE(PASSED))
		key_test->attributes.lifetime = lifetime;

	ret = key_read_policy(&key_test->attributes, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'id' parameter if defined */
	ret = util_read_json_type(&id, ID_OBJ, t_int, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (ret == ERR_CODE(PASSED))
		key_test->attributes.id = id;

	ret = keypair_read(key_test, data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	return ERR_CODE(PASSED);
}

int key_desc_init_psa(struct keypair_psa *key_test)
{
	if (!key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	key_test->attributes = PSA_KEY_ATTRIBUTES_INIT;
	key_test->data = NULL;
	key_test->data_length = 0;

	return ERR_CODE(PASSED);
}

int key_read_descriptor_psa(struct llist *keys, struct keypair_psa *key_test,
			    const char *key_name)
{
	int res = ERR_CODE(PASSED);
	int err = ERR_CODE(PASSED);

	struct llist *key_names = NULL;

	res = util_list_init(&key_names, NULL, LIST_ID_TYPE_STRING);

	if (res == ERR_CODE(PASSED))
		res = read_descriptor(keys, key_test, key_name, key_names);

	err = util_list_clear(key_names);
	if (res == ERR_CODE(PASSED))
		res = err;

	return res;
}

void key_prepare_key_data_psa(struct keypair_psa *key_test,
			      struct key_data *key_data)
{
	key_data->identifier = key_test->attributes.id;
	key_data->pub_key.data = NULL;
	key_data->pub_key.length = 0;
}
