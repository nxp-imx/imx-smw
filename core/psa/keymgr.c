// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include "smw_keymgr.h"

#include "psa/crypto.h"

#include "compiler.h"
#include "debug.h"
#include "utils.h"
#include "tlv.h"
#include "config.h"
#include "keymgr.h"

#include "common.h"
#include "util_status.h"

#define ASN1_TAG_SEQUENCE	 0x30 /* (16 | 0x20) */
#define ASN1_TAG_INTEGER	 2
#define ASN1_LENGTH_FIELD_LENGTH 1
#define ASN1_TAG_FIELD_LENGTH	 1

#define KEY_TYPE(_smw, _psa)                                                   \
	{                                                                      \
		.smw_key_type = _smw, .psa_key_type = PSA_KEY_TYPE_##_psa,     \
	}

/**
 * struct - Key type
 * @smw_key_type: SMW key type name.
 * @psa_key_type: PSA key type.
 */
static const struct key_type {
	smw_key_type_t smw_key_type;
	psa_key_type_t psa_key_type;
} key_type[] = { KEY_TYPE("AES", AES),
		 KEY_TYPE("DES", DES),
		 KEY_TYPE("SM4", SM4),
		 KEY_TYPE("RSA", RSA_KEY_PAIR),
		 KEY_TYPE("RSA", RSA_PUBLIC_KEY),
		 KEY_TYPE("DH", DH_KEY_PAIR_BASE) };

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
	HMAC_HASH("HMAC_MD5", MD5),	   HMAC_HASH("HMAC_SHA1", SHA_1),
	HMAC_HASH("HMAC_SHA224", SHA_224), HMAC_HASH("HMAC_SHA256", SHA_256),
	HMAC_HASH("HMAC_SHA384", SHA_384), HMAC_HASH("HMAC_SHA512", SHA_512),
	HMAC_HASH("HMAC_SM3", SM3)
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

static smw_key_type_t get_hmac_key_type(psa_algorithm_t psa_hash)
{
	unsigned int i;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (i = 0; i < ARRAY_SIZE(hmac_hash); i++) {
		if (hmac_hash[i].psa_hash == psa_hash)
			return hmac_hash[i].smw_key_type;
	}

	return NULL;
}

static smw_key_type_t get_ecc_key_type(psa_ecc_family_t ecc_family,
				       psa_algorithm_t psa_hash)
{
	unsigned int i;
	unsigned int array_size = 0;
	const struct ecc_key_type *array = NULL;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (PSA_ALG_IS_ECDSA(psa_hash)) {
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

static smw_key_type_t get_key_type(const psa_key_attributes_t *attributes)
{
	unsigned int i;

	psa_key_type_t psa_key_type;
	psa_algorithm_t hash;
	psa_ecc_family_t ecc_family;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!attributes)
		return NULL;

	psa_key_type = psa_get_key_type(attributes);

	if (PSA_KEY_TYPE_IS_DH(psa_key_type))
		psa_key_type = PSA_KEY_TYPE_DH_KEY_PAIR_BASE;

	for (i = 0; i < ARRAY_SIZE(key_type); i++) {
		if (key_type[i].psa_key_type == psa_key_type)
			return key_type[i].smw_key_type;
	}

	if (psa_key_type == PSA_KEY_TYPE_HMAC) {
		hash = PSA_ALG_GET_HASH(psa_get_key_algorithm(attributes));
		return get_hmac_key_type(hash);
	}

	if (PSA_KEY_TYPE_IS_ECC(psa_key_type)) {
		ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_key_type);
		hash = PSA_ALG_GET_HASH(psa_get_key_algorithm(attributes));
		return get_ecc_key_type(ecc_family, hash);
	}

	return NULL;
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
		l = (alg & PSA_ALG_MAC_TRUNCATION_MASK) >>
		    PSA_MAC_TRUNCATION_OFFSET;

		if (alg & PSA_ALG_MAC_AT_LEAST_THIS_LENGTH_FLAG)
			*min_length = l;
		else
			*length = l;
	}
}

static int set_key_algo(psa_algorithm_t alg, unsigned char **tlv,
			unsigned int *tlv_length)
{
	int status = SMW_STATUS_OK;

	const char *alg_str = NULL;
	const char *hash_str = NULL;
	const char *kdf_str = NULL;
	unsigned int alg_len = 0;
	unsigned int hash_len = 0;
	unsigned int kdf_len = 0;
	uint8_t length = 0;
	uint8_t min_length = 0;
	unsigned char *p;
	unsigned char *kdf_tlv;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*tlv = NULL;
	*tlv_length = 0;

	if (!alg)
		goto end;

	get_alg_name(alg, &alg_str, &hash_str, &kdf_str, &length, &min_length);

	if (alg_str)
		alg_len = SMW_UTILS_STRLEN(alg_str);

	if (!alg_str || !alg_len) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

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
	if (!*tlv) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

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

end:
	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
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

static int set_key_attributes_list(const psa_key_attributes_t *attributes,
				   unsigned char **key_attributes_list,
				   unsigned int *key_attributes_list_length)
{
	int status = SMW_STATUS_OK;

	unsigned char *p;
	unsigned int i;
	psa_key_usage_t usage_flags;
	unsigned char *policy_tlv = NULL;
	unsigned char *usage_tlv = NULL;
	unsigned char *algo_v = NULL;
	unsigned int algo_v_length = 0;
	unsigned int algo_tlv_length = 0;
	unsigned int usage_tlv_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*key_attributes_list = NULL;
	*key_attributes_list_length = 0;

	if (!attributes) {
		status = SMW_STATUS_INVALID_PARAM;
		goto end;
	}

	usage_flags = psa_get_key_usage_flags(attributes);

	status = set_key_algo(psa_get_key_algorithm(attributes), &algo_v,
			      &algo_v_length);
	if (status != SMW_STATUS_OK)
		goto end;

	if (algo_v_length)
		algo_tlv_length =
			SMW_TLV_ELEMENT_LENGTH(ALGO_STR, algo_v_length);

	usage_tlv_length = get_usage_tlv_length(usage_flags, algo_tlv_length);

	*key_attributes_list_length =
		SMW_TLV_ELEMENT_LENGTH(POLICY_STR, usage_tlv_length);

	if (!PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime))
		*key_attributes_list_length +=
			SMW_TLV_ELEMENT_LENGTH(PERSISTENT_STR, 0);

	*key_attributes_list = SMW_UTILS_MALLOC(*key_attributes_list_length);
	if (!*key_attributes_list) {
		status = SMW_STATUS_ALLOC_FAILURE;
		goto end;
	}

	p = *key_attributes_list;

	if (!PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime))
		smw_tlv_set_boolean(&p, PERSISTENT_STR);

	policy_tlv = p;
	smw_tlv_set_type(&p, POLICY_STR);

	for (i = 0; i < ARRAY_SIZE(key_usage); i++) {
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
	if (status != SMW_STATUS_OK) {
		if (*key_attributes_list)
			free(*key_attributes_list);
	}

	if (algo_v)
		free(algo_v);

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static psa_status_t export_key_common(psa_key_id_t key, uint8_t *data,
				      size_t data_size, size_t *data_length)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_export_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };
	unsigned int public_length = 0;
	unsigned int modulus_length = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	key_descriptor.id = key;

	status = smw_get_key_type_name(&key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	key_descriptor.buffer = &keypair_buffer;
	status = smw_get_key_buffers_lengths(&key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	if (!SMW_UTILS_STRCMP(key_descriptor.type_name, "RSA")) {
		/* RSA KEY */
		public_length = keypair_buffer.rsa.public_length;
		modulus_length = keypair_buffer.rsa.modulus_length;
		*data_length = modulus_length +
			       public_length
			       /* SEQUENCE */
			       + ASN1_TAG_FIELD_LENGTH +
			       ASN1_LENGTH_FIELD_LENGTH
			       /* INTEGER - modulus */
			       + ASN1_TAG_FIELD_LENGTH +
			       ASN1_LENGTH_FIELD_LENGTH
			       /* INTEGER - publicExponent */
			       + ASN1_TAG_FIELD_LENGTH +
			       ASN1_LENGTH_FIELD_LENGTH;

		if (data_size < *data_length)
			return PSA_ERROR_BUFFER_TOO_SMALL;

		/*
		 *	RSAPublicKey ::= SEQUENCE {
		 *	   modulus            INTEGER,    -- n
		 *	   publicExponent     INTEGER  }  -- e
		 */

		keypair_buffer.rsa.modulus = data
					     /* SEQUENCE */
					     + ASN1_TAG_FIELD_LENGTH +
					     ASN1_LENGTH_FIELD_LENGTH
					     /* INTEGER - modulus */
					     + ASN1_TAG_FIELD_LENGTH +
					     ASN1_LENGTH_FIELD_LENGTH;

		keypair_buffer.rsa.public_data = keypair_buffer.rsa.modulus
						 /* INTEGER  - publicExponent */
						 + ASN1_TAG_FIELD_LENGTH +
						 ASN1_LENGTH_FIELD_LENGTH +
						 modulus_length;

		/* Tag SEQUENCE */
		data[0] = ASN1_TAG_SEQUENCE;

		/* Length */
		data[1] =
			/* INTEGER - modulus */
			ASN1_TAG_FIELD_LENGTH +
			ASN1_LENGTH_FIELD_LENGTH
			/* INTEGER - publicExponent */
			+ ASN1_TAG_FIELD_LENGTH + ASN1_LENGTH_FIELD_LENGTH +
			modulus_length + public_length;

		/* Tag INTEGER */
		data[2] = ASN1_TAG_INTEGER;

		/* Length */
		data[3] = modulus_length;

		/* Tag INTEGER */
		data[4 + modulus_length] = ASN1_TAG_INTEGER;

		/* Length */
		data[5 + modulus_length] = public_length;

	} else {
		if (!keypair_buffer.gen.public_length)
			return PSA_ERROR_NOT_SUPPORTED;

		*data_length = keypair_buffer.gen.public_length;

		if (data_size < *data_length)
			return PSA_ERROR_BUFFER_TOO_SMALL;

		keypair_buffer.gen.public_data = data;
	}

	args.key_descriptor = &key_descriptor;

	status = smw_export_key(&args);

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
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_generate_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_config_psa_config config;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	if (!attributes)
		return PSA_ERROR_INVALID_ARGUMENT;

	smw_config_get_psa_config(&config);

	key_descriptor.type_name = get_key_type(attributes);
	if (!key_descriptor.type_name)
		return PSA_ERROR_NOT_SUPPORTED;

	key_descriptor.security_size = psa_get_key_bits(attributes);

	args.subsystem_name = get_subsystem_name(&config);
	status = set_key_attributes_list(attributes, &args.key_attributes_list,
					 &args.key_attributes_list_length);
	if (status != SMW_STATUS_OK)
		goto end;

	args.key_descriptor = &key_descriptor;

	status = call_smw_api((enum smw_status_code(*)(void *))smw_generate_key,
			      &args, &config, &args.subsystem_name);

	if (status == SMW_STATUS_OK ||
	    status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
		*key = key_descriptor.id;

end:
	return util_smw_to_psa_status(status);
}

__export psa_status_t psa_get_key_attributes(psa_key_id_t key,
					     psa_key_attributes_t *attributes)
{
	(void)key;
	(void)attributes;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return PSA_ERROR_NOT_SUPPORTED;
}

__export psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
				     const uint8_t *data, size_t data_length,
				     psa_key_id_t *key)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_import_key_args args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };
	struct smw_config_psa_config config;
	psa_key_type_t key_type;
	unsigned int modulus_length_offset;
	unsigned int version_length_offset;

	SMW_DBG_TRACE_FUNCTION_CALL;

	if (!smw_utils_is_lib_initialized())
		return PSA_ERROR_BAD_STATE;

	if (!attributes)
		return PSA_ERROR_INVALID_ARGUMENT;

	smw_config_get_psa_config(&config);

	key_descriptor.type_name = get_key_type(attributes);
	if (!key_descriptor.type_name)
		return PSA_ERROR_NOT_SUPPORTED;

	key_descriptor.security_size = psa_get_key_bits(attributes);

	key_descriptor.buffer = &keypair_buffer;

	key_type = psa_get_key_type(attributes);
	if (PSA_KEY_TYPE_IS_RSA(key_type)) {
		if (PSA_KEY_TYPE_IS_KEY_PAIR(key_type)) {
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

			version_length_offset = /* SEQUENCE */
				ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH
				/* INTEGER - version */
				+ ASN1_TAG_FIELD_LENGTH;

			modulus_length_offset = /* SEQUENCE */
				ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH
				/* INTEGER - version */
				+ ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH +
				data[version_length_offset]
				/* INTEGER - modulus */
				+ ASN1_TAG_FIELD_LENGTH;

			keypair_buffer.rsa.modulus_length =
				data[modulus_length_offset];
			keypair_buffer.rsa.modulus = (unsigned char *)data +
						     modulus_length_offset +
						     ASN1_LENGTH_FIELD_LENGTH;
			keypair_buffer.rsa.public_length =
				*(keypair_buffer.rsa.modulus +
				  keypair_buffer.rsa.modulus_length +
				  ASN1_TAG_FIELD_LENGTH);
			keypair_buffer.rsa.public_data =
				(unsigned char *)keypair_buffer.rsa.modulus +
				keypair_buffer.rsa.modulus_length +
				ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH;
			keypair_buffer.rsa.private_length =
				*(keypair_buffer.rsa.public_data +
				  keypair_buffer.rsa.public_length +
				  ASN1_TAG_FIELD_LENGTH);
			keypair_buffer.rsa.private_data =
				(unsigned char *)keypair_buffer.rsa.public_data +
				keypair_buffer.rsa.public_length +
				ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH;
		} else if (PSA_KEY_TYPE_IS_PUBLIC_KEY(key_type)) {
			/*
			 *	RSAPublicKey ::= SEQUENCE {
			 *	   modulus            INTEGER,    -- n
			 *	   publicExponent     INTEGER  }  -- e
			 */

			modulus_length_offset = /* SEQUENCE */
				ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH
				/* INTEGER - modulus */
				+ ASN1_TAG_FIELD_LENGTH;

			keypair_buffer.rsa.modulus_length =
				data[modulus_length_offset];
			keypair_buffer.rsa.modulus = (unsigned char *)data +
						     modulus_length_offset +
						     ASN1_LENGTH_FIELD_LENGTH;
			keypair_buffer.rsa.public_length =
				*(keypair_buffer.rsa.modulus +
				  keypair_buffer.rsa.modulus_length +
				  ASN1_TAG_FIELD_LENGTH);
			keypair_buffer.rsa.public_data =
				(unsigned char *)keypair_buffer.rsa.modulus +
				keypair_buffer.rsa.modulus_length +
				ASN1_TAG_FIELD_LENGTH +
				ASN1_LENGTH_FIELD_LENGTH;
		} else {
			return PSA_ERROR_NOT_SUPPORTED;
		}
	} else if (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type) ||
		   PSA_KEY_TYPE_IS_ECC(key_type)) {
		keypair_buffer.gen.private_data = (unsigned char *)data;
		keypair_buffer.gen.private_length = data_length;
	} else {
		return PSA_ERROR_NOT_SUPPORTED;
	}

	args.subsystem_name = get_subsystem_name(&config);
	status = set_key_attributes_list(attributes, &args.key_attributes_list,
					 &args.key_attributes_list_length);
	if (status != SMW_STATUS_OK)
		goto end;

	args.key_descriptor = &key_descriptor;

	status = call_smw_api((enum smw_status_code(*)(void *))smw_import_key,
			      &args, &config, &args.subsystem_name);

	if (status == SMW_STATUS_OK ||
	    status == SMW_STATUS_KEY_POLICY_WARNING_IGNORED)
		*key = key_descriptor.id;

end:
	return util_smw_to_psa_status(status);
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
