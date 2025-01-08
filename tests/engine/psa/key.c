// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <json.h>

#include <psa/crypto.h>

#include "types.h"
#include "util.h"
#include "util_attr.h"
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

#define DH_STR	     "DH"
#define RSA_STR	     "RSA"
#define KEYPAIR_STR  "KEYPAIR"
#define RAW_DATA_STR "RAW_DATA"

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

#define KEY_TYPE(_string, _psa)                                                \
	{                                                                      \
		.key_type_string = _string,                                    \
		.psa_key_type = PSA_KEY_TYPE_##_psa,                           \
	}

/**
 * struct - Key type
 * @key_type_string: Key type string.
 * @psa_key_type: PSA key type.
 */
static const struct cipher_key_type {
	const char *key_type_string;
	psa_key_type_t psa_key_type;
} cipher_key_type[] = { KEY_TYPE("AES", AES), KEY_TYPE("DES", DES),
			KEY_TYPE("DES3", DES), KEY_TYPE("SM4", SM4) };

#define ECC_KEY_TYPE(_string, _family)                                         \
	{                                                                      \
		.key_type_string = _string,                                    \
		.ecc_family = PSA_ECC_FAMILY_##_family                         \
	}

/**
 * struct - ECC key type
 * @key_type_string: SMW HMAC key type string.
 * @ecc_family: Elliptic curve family.
 */
struct ecc_key_type {
	const char *key_type_string;
	psa_ecc_family_t ecc_family;
};

static const struct ecc_key_type ecc_key_type[] = {
	ECC_KEY_TYPE("SECP_R1", SECP_R1),
	ECC_KEY_TYPE("BRAINPOOL_R1", BRAINPOOL_P_R1),
	ECC_KEY_TYPE("ED25519", TWISTED_EDWARDS)
};

#define KEY_HASH(_string)                                                      \
	{                                                                      \
		.hash_str = _string##_STR, .psa_hash = PSA_ALG_##_string       \
	}

#define KEY_ALGORITHM(_string)                                                 \
	{                                                                      \
		.alg_str = _string##_STR, .psa_alg = PSA_ALG_##_string         \
	}

#define KEY_USAGE(_string, _restricted)                                        \
	{                                                                      \
		.usage_str = _string##_STR,                                    \
		.psa_usage = PSA_KEY_USAGE_##_string,                          \
		.restricted = _restricted                                      \
	}

static const struct {
	const char *persistence_str;
	psa_key_persistence_t psa_persistence;
} key_persistence[] = {
	{ "TRANSIENT", PSA_KEY_PERSISTENCE_VOLATILE },
	{ "PERSISTENT", PSA_KEY_PERSISTENCE_DEFAULT },
	{ "PERMANENT", PSA_KEY_PERSISTENCE_READ_ONLY },
};

static psa_key_type_t get_ecc_psa_key_type(const char *key_type_string,
					   const char *privacy_string)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	bool is_keypair = false;
	psa_ecc_family_t ecc_family = 0;
	unsigned int i = 0;

	if (!privacy_string)
		return psa_key_type;

	for (; !ecc_family && i < ARRAY_SIZE(ecc_key_type); i++) {
		if (!strcmp(ecc_key_type[i].key_type_string, key_type_string))
			ecc_family = ecc_key_type[i].ecc_family;
	}

	if (!ecc_family)
		return psa_key_type;

	if (!strcmp(privacy_string, KEYPAIR_STR))
		is_keypair = true;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_family);
	else
		psa_key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(ecc_family);

	return psa_key_type;
}

static psa_key_type_t get_dh_psa_key_type(const char *key_type_string,
					  const char *privacy_string)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	bool is_keypair = false;

	if (strcmp(key_type_string, DH_STR) || !privacy_string)
		return psa_key_type;

	if (!strcmp(privacy_string, KEYPAIR_STR))
		is_keypair = true;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_DH_KEY_PAIR(PSA_DH_FAMILY_RFC7919);
	else
		psa_key_type =
			PSA_KEY_TYPE_DH_PUBLIC_KEY(PSA_DH_FAMILY_RFC7919);

	return psa_key_type;
}

static psa_key_type_t get_rsa_psa_key_type(const char *key_type_string,
					   const char *privacy_string)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;
	bool is_keypair = false;

	if (strcmp(key_type_string, RSA_STR) || !privacy_string)
		return psa_key_type;

	if (!strcmp(privacy_string, KEYPAIR_STR))
		is_keypair = true;

	if (is_keypair)
		psa_key_type = PSA_KEY_TYPE_RSA_KEY_PAIR;
	else
		psa_key_type = PSA_KEY_TYPE_RSA_PUBLIC_KEY;

	return psa_key_type;
}

static psa_key_type_t get_hmac_psa_key_type(const char *key_type_string)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;

	if (!strncmp(key_type_string, HMAC_STR, strlen(HMAC_STR)))
		psa_key_type = PSA_KEY_TYPE_HMAC;

	return psa_key_type;
}

psa_key_type_t get_cipher_psa_key_type(const char *key_type_string)
{
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_key_type); i++) {
		if (!strcmp(cipher_key_type[i].key_type_string,
			    key_type_string))
			return cipher_key_type[i].psa_key_type;
	}

	return PSA_KEY_TYPE_NONE;
}

static psa_key_type_t get_raw_psa_key_type(const char *key_type_string)
{
	psa_key_type_t psa_key_type = PSA_KEY_TYPE_NONE;

	if (!strncmp(key_type_string, RAW_DATA_STR, strlen(RAW_DATA_STR)))
		psa_key_type = PSA_KEY_TYPE_RAW_DATA;

	return psa_key_type;
}

static int get_psa_key_type(psa_key_type_t *psa_key_type,
			    const char *key_type_string,
			    const char *privacy_string)
{
	int ret = ERR_CODE(BAD_PARAM_TYPE);

	if (!psa_key_type)
		return ERR_CODE(BAD_ARGS);

	if (!key_type_string)
		return ret;

	*psa_key_type = get_dh_psa_key_type(key_type_string, privacy_string);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type =
			get_rsa_psa_key_type(key_type_string, privacy_string);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type =
			get_ecc_psa_key_type(key_type_string, privacy_string);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type = get_hmac_psa_key_type(key_type_string);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type = get_cipher_psa_key_type(key_type_string);
	if (*psa_key_type == PSA_KEY_TYPE_NONE)
		*psa_key_type = get_raw_psa_key_type(key_type_string);
	if (*psa_key_type != PSA_KEY_TYPE_NONE)
		ret = ERR_CODE(PASSED);

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

static const struct util_attr_info usage_info_psa[] = {
	ATTR_USAGE_PSA(CACHE),
	ATTR_USAGE_PSA(COPY),
	ATTR_USAGE_PSA(DERIVE),
	ATTR_USAGE_PSA(ENCRYPT),
	ATTR_USAGE_PSA(DECRYPT),
	ATTR_USAGE_PSA(SIGN_HASH),
	ATTR_USAGE_PSA(SIGN_MESSAGE),
	ATTR_USAGE_PSA(VERIFY_HASH),
	ATTR_USAGE_PSA(VERIFY_MESSAGE),
	ATTR_USAGE_PSA(VERIFY_DERIVATION),
	{ .string = NULL }
};

static void usage_callback(void *user_data, const char *attributes[],
			   size_t n_attributes)
{
	psa_key_usage_t *usage_flags = user_data;
	size_t i = 0;

	for (; i < n_attributes; i++)
		*usage_flags |=
			ATTR_ARRAY_FIND_MATCH(usage_info_psa, attributes[i])
				.psa_usage;

	DBG_PRINT("PSA usage flags: %08x", *usage_flags);
}

static const struct util_attr_info algo_info_psa[] = {
	ATTR_ALGO_PSA(ECB_NO_PADDING, PSA_ALG_ECB_NO_PADDING),
	ATTR_ALGO_PSA(CFB, PSA_ALG_CFB),
	ATTR_ALGO_PSA(CTR, PSA_ALG_CTR),
	ATTR_ALGO_PSA(OFB, PSA_ALG_OFB),
	ATTR_ALGO_PSA(XTS, PSA_ALG_XTS),
	ATTR_ALGO_PSA(CCM, PSA_ALG_CCM),
	ATTR_ALGO_PSA(GCM, PSA_ALG_GCM),
	ATTR_ALGO_PSA(CHACHA20_POLY1305, PSA_ALG_CHACHA20_POLY1305),
	ATTR_ALGO_PSA(CMAC, PSA_ALG_CMAC),
	ATTR_ALGO_PSA(HMAC, PSA_ALG_HMAC(PSA_ALG_NONE)),
	ATTR_ALGO_PSA(ECDSA, PSA_ALG_ECDSA_BASE),
	ATTR_ALGO_PSA(ED25519PH, PSA_ALG_ED25519PH),
	ATTR_ALGO_PSA(ED448PH, PSA_ALG_ED448PH),
	ATTR_ALGO_PSA(PURE_EDDSA, PSA_ALG_PURE_EDDSA),
	ATTR_ALGO_PSA(DETERMINISTIC_ECDSA, PSA_ALG_DETERMINISTIC_ECDSA_BASE),
	ATTR_ALGO_PSA(HASH_EDDSA, PSA_ALG_HASH_EDDSA_BASE),
	ATTR_ALGO_PSA(RSA_PKCS1V15, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_NONE)),
	ATTR_ALGO_PSA(RSA_PSS, PSA_ALG_RSA_PSS_ANY_SALT(PSA_ALG_NONE)),
	ATTR_ALGO_PSA(RSA_PKCS1V15_SIGN_RAW, PSA_ALG_RSA_PKCS1V15_SIGN_RAW),
	ATTR_ALGO_PSA(RSA_PKCS1V15_SIGN_BASE, PSA_ALG_RSA_PKCS1V15_SIGN_BASE),
	ATTR_ALGO_PSA(RSA_PSS_ANY_SALT, PSA_ALG_RSA_PSS_ANY_SALT_BASE),
	ATTR_ALGO_PSA(RSA_PSS, PSA_ALG_RSA_PSS_BASE),
	{ .string = NULL }
};

static const struct util_attr_info hash_info_psa[] = {
	ATTR_HASH_PSA(MD5, PSA_ALG_MD5),
	ATTR_HASH_PSA(SHA1, PSA_ALG_SHA_1),
	ATTR_HASH_PSA(SHA224, PSA_ALG_SHA_224),
	ATTR_HASH_PSA(SHA256, PSA_ALG_SHA_256),
	ATTR_HASH_PSA(SHA384, PSA_ALG_SHA_384),
	ATTR_HASH_PSA(SHA512, PSA_ALG_SHA_512),
	ATTR_HASH_PSA(SHA3_SHA224, PSA_ALG_SHA3_224),
	ATTR_HASH_PSA(SHA3_SHA256, PSA_ALG_SHA3_256),
	ATTR_HASH_PSA(SHA3_SHA384, PSA_ALG_SHA3_384),
	ATTR_HASH_PSA(SHA3_SHA512, PSA_ALG_SHA3_512),
	ATTR_HASH_PSA(ANY_HASH, PSA_ALG_ANY_HASH),
	{ .string = NULL }
};

void algorithm_callback_psa(void *user_data, const char *params[],
			    size_t n_params)
{
	psa_algorithm_t *alg = user_data;
	size_t i = 1;
	const char *param = NULL;
	psa_algorithm_t length = 0;
	bool min_length = false;

	*alg = ATTR_ARRAY_FIND_MATCH(algo_info_psa, params[0]).psa_algo;

	for (; i < n_params; i++) {
		param = params[i];

		if (!strncmp(param, HASH_STR, strlen(HASH_STR))) {
			param = param + strlen(HASH_STR);
			*alg |= ATTR_ARRAY_FIND_MATCH(hash_info_psa, param)
					.psa_algo;
		} else if (!strncmp(param, MIN_LENGTH_STR,
				    strlen(MIN_LENGTH_STR))) {
			(void)SET_OVERFLOW(atol(param + strlen(MIN_LENGTH_STR)),
					   length);

			min_length = true;
		} else if (!strncmp(param, LENGTH_STR, strlen(LENGTH_STR))) {
			(void)SET_OVERFLOW(atol(param + strlen(LENGTH_STR)),
					   length);

			min_length = false;
		}
	}

	if (length) {
		if (PSA_ALG_IS_AEAD(*alg)) {
			*alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(*alg, length);
			if (min_length)
				*alg |= PSA_ALG_AEAD_AT_LEAST_THIS_LENGTH_FLAG;
		} else if (PSA_ALG_IS_MAC(*alg)) {
			*alg = PSA_ALG_TRUNCATED_MAC(*alg, length);
			if (min_length)
				*alg |= PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG;
		}
	}

	DBG_PRINT("PSA algorithm: %08x", *alg);
}

static const struct util_attr_info lifetime_info_psa[] = {
	ATTR_LIFETIME_PSA(VOLATILE),
	ATTR_LIFETIME_PSA(PERSISTENT),
	{ .string = NULL }
};

static void attributes_callback(void *user_data, const char *attributes[],
				size_t n_attributes)
{
	psa_key_attributes_t *attr = user_data;

	size_t i = 0;

	for (; i < n_attributes; i++)
		attr->lifetime |=
			ATTR_ARRAY_FIND_MATCH(lifetime_info_psa, attributes[i])
				.psa_lifetime;

	DBG_PRINT("PSA lifetime: %08x", attr->lifetime);
}

static int key_read_policy(psa_key_attributes_t *attributes,
			   struct json_object *okey)
{
	int ret = ERR_CODE(BAD_ARGS);

	if (!okey || !attributes) {
		DBG_PRINT_BAD_ARGS();
		return ret;
	}

	ret = util_attr_read_attributes(okey, USAGE_OBJ, &usage_callback,
					&attributes->usage_flags);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_attr_read_attributes(okey, PERMITTED_ALGO_OBJ,
					&algorithm_callback_psa,
					&attributes->alg);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	ret = util_attr_read_attributes(okey, ATTR_LIST_OBJ,
					&attributes_callback, &attributes);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (ret == ERR_CODE(VALUE_NOTFOUND))
		ret = ERR_CODE(PASSED);

	ret = ERR_CODE(PASSED);
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
	const char *format_string = NULL;

	if (!params || !key_test) {
		DBG_PRINT_BAD_ARGS();
		return ERR_CODE(BAD_ARGS);
	}

	if (json_object_object_get_ex(params, FORMAT_OBJ, &okey))
		format_string = json_object_get_string(okey);

	if (json_object_object_get_ex(params, KEY_DATA_OBJ, &okey)) {
		ret = read_key(&key_test->data, &key_test->data_length,
			       format_string, okey);

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
	const char *privacy_string = KEYPAIR_STR;
	const char *type_string = NULL;
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
	}

	/* Read 'privacy' parameter if defined */
	ret = util_read_json_type(&privacy_string, PRIVACY_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	/* Read 'type' parameter if defined */
	ret = util_read_json_type(&type_string, TYPE_OBJ, t_string,
				  data->okey_params);
	if (ret != ERR_CODE(PASSED) && ret != ERR_CODE(VALUE_NOTFOUND))
		return ret;

	if (type_string) {
		ret = get_psa_key_type(&psa_key_type, type_string,
				       privacy_string);
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
	ret = util_read_json_type(&id, ID_OBJ, t_uint, data->okey_params);
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
