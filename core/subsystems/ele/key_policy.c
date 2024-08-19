// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024 NXP
 */

#include <inttypes.h>

#include "smw/attr.h"
#include "debug.h"

#include "common.h"

#define KEY_USAGE(_smw, _ele)                                                  \
	{                                                                      \
		.smw = SMW_ATTR_USAGE_##_smw, .ele = HSM_KEY_USAGE_##_ele,     \
	}

static const struct {
	smw_attr_usage_t smw;
	hsm_key_usage_t ele;
} key_usage[] = { KEY_USAGE(EXPORT, EXPORT),
		  KEY_USAGE(ENCRYPT, ENCRYPT),
		  KEY_USAGE(DECRYPT, DECRYPT),
		  KEY_USAGE(SIGN_MESSAGE, SIGN_MSG),
		  KEY_USAGE(VERIFY_MESSAGE, VERIFY_MSG),
		  KEY_USAGE(SIGN_HASH, SIGN_HASH),
		  KEY_USAGE(VERIFY_HASH, VERIFY_HASH),
		  KEY_USAGE(DERIVE, DERIVE) };

#define PERMITTED_ALGO(_ele_permitted_algo, _smw_algo, _smw_mode, _smw_hash,   \
		       _smw_class)                                             \
	{                                                                      \
		.ele_permitted_algo = PERMITTED_ALGO_##_ele_permitted_algo,    \
		.smw_algo = SMW_ATTR_ALGO_##_smw_algo,                         \
		.smw_mode = SMW_ATTR_MODE_##_smw_mode,                         \
		.smw_hash = SMW_ATTR_HASH_##_smw_hash,                         \
		.smw_class = SMW_ATTR_CLASS_##_smw_class,                      \
	}

#define PERMITTED_ALGO_CURVE(_ele_permitted_algo, _smw_algo, _smw_curve,       \
			     _smw_hash, _smw_class)                            \
	{                                                                      \
		.ele_permitted_algo = PERMITTED_ALGO_##_ele_permitted_algo,    \
		.smw_algo = SMW_ATTR_ALGO_##_smw_algo,                         \
		.smw_curve = SMW_ATTR_CURVE_##_smw_curve,                      \
		.smw_hash = SMW_ATTR_HASH_##_smw_hash,                         \
		.smw_class = SMW_ATTR_CLASS_##_smw_class,                      \
	}

#define ELE_MIN_LENGTH_BIT ((hsm_permitted_algo_t)BIT(15))
#define ELE_LENGTH_OFFSET  16u
#define ELE_LENGTH_MASK	   ((hsm_permitted_algo_t)0x3F)
#define ELE_LENGTH_MASK_OFFSET                                                 \
	((hsm_permitted_algo_t)ELE_LENGTH_MASK << ELE_LENGTH_OFFSET)

static const struct {
	hsm_permitted_algo_t ele_permitted_algo;
	smw_attr_algo_t smw_algo;
	union {
		smw_attr_algo_t smw_mode;
		smw_attr_algo_t smw_curve;
	};
	smw_attr_algo_t smw_hash;
	smw_attr_algo_t smw_class;
} permitted_algos[] = {
	PERMITTED_ALGO(HMAC_SHA256, HMAC, NONE, SHA256, MAC),
	PERMITTED_ALGO(HMAC_SHA384, HMAC, NONE, SHA384, MAC),
	PERMITTED_ALGO(CMAC, DEFAULT, CMAC, NONE, MAC),
	PERMITTED_ALGO(CTR, DEFAULT, CTR, NONE, SYMMETRIC_ENCRYPTION),
	PERMITTED_ALGO(CFB, DEFAULT, CFB, NONE, SYMMETRIC_ENCRYPTION),
	PERMITTED_ALGO(OFB, DEFAULT, OFB, NONE, SYMMETRIC_ENCRYPTION),
	PERMITTED_ALGO(ECB_NO_PADDING, DEFAULT, ECB_NO_PAD, NONE,
		       SYMMETRIC_ENCRYPTION),
	PERMITTED_ALGO(CBC_NO_PADDING, DEFAULT, CBC_NO_PAD, NONE,
		       SYMMETRIC_ENCRYPTION),
	PERMITTED_ALGO(CCM, DEFAULT, CCM, NONE, AEAD),
	PERMITTED_ALGO(GCM, DEFAULT, GCM, NONE, AEAD),
	PERMITTED_ALGO(CHACHA20_POLY1305, DEFAULT, POLY1305, NONE, AEAD),
	PERMITTED_ALGO(RSA_PKCS1_V15_SHA224, RSA, PKCS1_1_5, SHA224,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_V15_SHA256, RSA, PKCS1_1_5, SHA256,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_V15_SHA384, RSA, PKCS1_1_5, SHA384,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_V15_SHA512, RSA, PKCS1_1_5, SHA512,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_PSS_MGF1_SHA224, RSA, PSS, SHA224,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_PSS_MGF1_SHA256, RSA, PSS, SHA256,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_PSS_MGF1_SHA384, RSA, PSS, SHA384,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(RSA_PKCS1_PSS_MGF1_SHA512, RSA, PSS, SHA512,
		       ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO_CURVE(ECDSA_SHA224, ECDSA, NONE, SHA224,
			     ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO_CURVE(ECDSA_SHA256, ECDSA, NONE, SHA256,
			     ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO_CURVE(ECDSA_SHA384, ECDSA, NONE, SHA384,
			     ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO_CURVE(ECDSA_SHA512, ECDSA, NONE, SHA512,
			     ASYMMETRIC_SIGNATURE),
	PERMITTED_ALGO(HMAC_KDF_SHA256, HKDF, NONE, SHA256, KEY_DERIVATION),
	PERMITTED_ALGO(ALL_CIPHER, DEFAULT, ANY, NONE, SYMMETRIC_ENCRYPTION),
	PERMITTED_ALGO(ALL_AEAD, DEFAULT, ANY, NONE, AEAD),
	PERMITTED_ALGO(ECDH_HKDF_SHA256, ECDH, NONE, SHA256, KEY_DERIVATION),
	PERMITTED_ALGO(ECDH_HKDF_SHA384, ECDH, NONE, SHA384, KEY_DERIVATION),
	PERMITTED_ALGO(HKDF_EXTRACT_SHA256, HKDF_EXTRACT, NONE, SHA256,
		       KEY_DERIVATION),
	PERMITTED_ALGO(HKDF_EXTRACT_SHA384, HKDF_EXTRACT, NONE, SHA384,
		       KEY_DERIVATION),
	PERMITTED_ALGO(HKDF_EXPAND_SHA256, HKDF_EXPAND, NONE, SHA256,
		       KEY_DERIVATION),
	PERMITTED_ALGO(HKDF_EXPAND_SHA384, HKDF_EXPAND, NONE, SHA384,
		       KEY_DERIVATION),
	PERMITTED_ALGO(ATTEST_CMAC, DEFAULT, CMAC, NONE, KEY_ATTESTATION),
	PERMITTED_ALGO_CURVE(ATTEST_ECDSA_SHA224, ECDSA, NONE, SHA224,
			     KEY_ATTESTATION),
	PERMITTED_ALGO_CURVE(ATTEST_ECDSA_SHA256, ECDSA, NONE, SHA256,
			     KEY_ATTESTATION),
	PERMITTED_ALGO_CURVE(ATTEST_ECDSA_SHA384, ECDSA, NONE, SHA384,
			     KEY_ATTESTATION),
	PERMITTED_ALGO_CURVE(ATTEST_ECDSA_SHA512, ECDSA, NONE, SHA512,
			     KEY_ATTESTATION),
};

static void convert_usage_to_ele(smw_attr_usage_t smw, hsm_key_usage_t *ele)
{
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (key_usage[i].smw & smw)
			*ele |= key_usage[i].ele;
	}

	SMW_DBG_PRINTF(DEBUG,
		       "Usage flags - SMW: 0x%" PRIx32 "-> ELE: 0x%" PRIx32
		       "\n",
		       smw, *ele);
}

static void convert_usage_to_smw(hsm_key_usage_t ele, smw_attr_usage_t *smw)
{
	unsigned int i = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*smw = 0;

	for (; i < ARRAY_SIZE(key_usage); i++) {
		if (key_usage[i].ele & ele)
			*smw |= key_usage[i].smw;
	}

	SMW_DBG_PRINTF(DEBUG,
		       "Usage flags - ELE: 0x%" PRIx32 "-> SMW: 0x%" PRIx32
		       "\n",
		       ele, *smw);
}

static void convert_algo_to_ele(smw_attr_algo_t smw, hsm_permitted_algo_t *ele)
{
	unsigned int i = 0;
	smw_attr_algo_t algo = SMW_ATTR_GET_ALGO(smw);
	smw_attr_algo_t mode = SMW_ATTR_GET_MODE(smw);
	smw_attr_algo_t curve = SMW_ATTR_GET_CURVE(smw);
	smw_attr_algo_t hash = SMW_ATTR_GET_HASH(smw);
	smw_attr_algo_t class = SMW_ATTR_GET_CLASS(smw);
	smw_attr_algo_t length = SMW_ATTR_GET_LENGTH(smw);
	unsigned long ele_algo = 0;

	SMW_DBG_TRACE_FUNCTION_CALL;

	for (; i < ARRAY_SIZE(permitted_algos); i++) {
		if (permitted_algos[i].smw_class == class &&
		    (permitted_algos[i].smw_algo == algo ||
		     permitted_algos[i].smw_algo == SMW_ATTR_ALGO_DEFAULT) &&
		    (permitted_algos[i].smw_mode == SMW_ATTR_MODE_NONE ||
		     permitted_algos[i].smw_mode == mode ||
		     permitted_algos[i].smw_curve == SMW_ATTR_CURVE_NONE ||
		     permitted_algos[i].smw_curve == curve) &&
		    (permitted_algos[i].smw_hash == SMW_ATTR_HASH_NONE ||
		     permitted_algos[i].smw_hash == hash)

		) {
			ele_algo = permitted_algos[i].ele_permitted_algo;

			if (class == SMW_ATTR_CLASS_MAC) {
				length <<= ELE_LENGTH_OFFSET;
				ele_algo =
					SET_CLEAR_MASK(ele_algo, length,
						       ELE_LENGTH_MASK_OFFSET);

				if (SMW_ATTR_IS_MIN_LENGTH(smw))
					ele_algo |= ELE_MIN_LENGTH_BIT;
			}

			(void)SET_OVERFLOW(ele_algo, *ele);

			break;
		}
	}

	SMW_DBG_PRINTF(DEBUG,
		       "Permitted algo - SMW: 0x%" PRIx64 "-> ELE: 0x%" PRIx32
		       "\n",
		       smw, *ele);
}

static void convert_algo_to_smw(hsm_permitted_algo_t ele, smw_attr_algo_t *smw)
{
	unsigned int i = 0;
	smw_attr_algo_t length = (ele >> ELE_LENGTH_OFFSET) & ELE_LENGTH_MASK;
	bool min_length = (ele & ELE_MIN_LENGTH_BIT) ? true : false;
	unsigned long ele_algo = ele;
	smw_attr_algo_t mode = SMW_ATTR_MODE_NONE;
	smw_attr_algo_t hash = SMW_ATTR_HASH_NONE;

	SMW_DBG_TRACE_FUNCTION_CALL;

	*smw = 0;

	for (; i < ARRAY_SIZE(permitted_algos); i++) {
		ele_algo = ele;

		if (permitted_algos[i].smw_class == SMW_ATTR_CLASS_MAC) {
			ele_algo = SET_CLEAR_MASK(ele_algo, 0,
						  ELE_LENGTH_MASK_OFFSET);
			ele_algo &= ~ELE_MIN_LENGTH_BIT;
		}

		if (permitted_algos[i].ele_permitted_algo == ele_algo) {
			mode = permitted_algos[i].smw_mode;
			hash = permitted_algos[i].smw_hash;

			*smw = (((permitted_algos[i].smw_class &
				  SMW_ATTR_CLASS_MASK)
				 << SMW_ATTR_CLASS_OFFSET) |
				((permitted_algos[i].smw_algo &
				  SMW_ATTR_ALGO_MASK)
				 << SMW_ATTR_ALGO_OFFSET) |
				((mode & (SMW_ATTR_MODE_MASK))
				 << SMW_ATTR_MODE_OFFSET) |
				((hash & (SMW_ATTR_HASH_MASK))
				 << SMW_ATTR_HASH_OFFSET));

			if (permitted_algos[i].smw_class ==
			    SMW_ATTR_CLASS_MAC) {
				if (min_length)
					*smw = SMW_ATTR_SET_MIN_LENGTH(*smw,
								       length);
				else
					*smw = SMW_ATTR_SET_LENGTH(*smw,
								   length);
			}

			break;
		}
	}

	SMW_DBG_PRINTF(DEBUG,
		       "Permitted algo - ELE: 0x%" PRIx32 "-> SMW: 0x%" PRIx64
		       "\n",
		       ele, *smw);
}

void ele_set_key_policy(hsm_permitted_algo_t *ele_permitted_algo,
			hsm_key_usage_t *ele_usage_flags,
			smw_attr_algo_t smw_permitted_algo,
			smw_attr_usage_t smw_usage_flags)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	convert_usage_to_ele(smw_usage_flags, ele_usage_flags);
	convert_algo_to_ele(smw_permitted_algo, ele_permitted_algo);
}

void ele_get_key_policy(smw_attr_algo_t *smw_permitted_algo,
			smw_attr_usage_t *smw_usage_flags,
			hsm_permitted_algo_t ele_permitted_algo,
			hsm_key_usage_t ele_usage_flags)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	convert_usage_to_smw(ele_usage_flags, smw_usage_flags);
	convert_algo_to_smw(ele_permitted_algo, smw_permitted_algo);
}
