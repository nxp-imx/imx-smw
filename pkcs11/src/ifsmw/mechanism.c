// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2024 NXP
 */

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <inttypes.h>

#include "smw_config.h"
#include "smw_crypto.h"
#include "smw_osal.h"
#include "smw/attr.h"
#include "smw/names.h"

#include "attributes.h"
#include "dev_config.h"
#include "lib_cipher.h"
#include "lib_context.h"
#include "lib_device.h"
#include "lib_object.h"
#include "lib_session.h"
#include "lib_digest.h"
#include "lib_sign_verify.h"
#include "libobj_types.h"
#include "pkcs11smw.h"
#include "types.h"

#include "args_attr.h"
#include "key_desc.h"
#include "ifsmw_utils.h"

#include "trace.h"

struct mgroup;
struct mentry;

static void check_mdigest(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mdigest(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mdigest(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_meckeygen(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			    struct mgroup *mgroup);
static CK_RV info_meckeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_meckeygen(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_mkeygen(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mkeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mkeygen(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_mkeyderive(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			     struct mgroup *mgroup);
static CK_RV info_mkeyderive(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			     struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mkeyderive(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_msign_ecdsa(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			      struct mgroup *mgroup);
static CK_RV info_msign_ecdsa(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_msign_ecdsa(CK_SLOT_ID slotid, struct mentry *entry,
			    void *args);
static void check_msign_rsa(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			    struct mgroup *mgroup);
static CK_RV info_msign_rsa(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_msign_rsa(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_mcipher(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mcipher(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mcipher(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_mcmac(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup);
static CK_RV info_mcmac(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mcmac(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_mhmac(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup);
static CK_RV info_mhmac(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mhmac(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static CK_RV info_maead(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static void check_maead(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup);
static CK_RV op_maead(CK_SLOT_ID slotid, struct mentry *entry, void *args);

smw_key_type_t smw_ec_name[] = { SMW_KEY_TYPE_NAME_SECP_R1,
				 SMW_KEY_TYPE_NAME_BRAINPOOL_R1,
				 SMW_KEY_TYPE_NAME_BRAINPOOL_T1 };

/**
 * struct mentry - Definition of a mechanism supported by each device
 * @type: Cryptoki Mechanism type
 * @slot_flag: Bit mask flag of a device supporting the mechanism
 * @smw_key_type: SMW key types name for this mechanism, if only one
 * @smw_hash: SMW hash name for this mechanism, if any
 * @smw_mac: SMW MAC name for this mechanism, if any
 * @smw_cipher_mode: SMW cipher mode name for this mechanism, if any
 * @smw_sign_algo: SMW signature algorithm name for this mechanism, if any
 * @smw_sign_type: SMW signature type name for this mechanism, if any
 * @smw_aead_mode: SMW AEAD mode name for this mechanism, if any
 * @smw_kdf: SMW Key Derivation Function name
 * @smw_algo_id: SMW permitted algorithm for this mechanism
 * @nb_smw_key_types: Number of SMW key types
 * @smw_key_types: SMW key types names for this mechanism, if more than one
 */
struct mentry {
	CK_MECHANISM_TYPE type;
	CK_FLAGS slot_flag;
	smw_key_type_t smw_key_type;
	smw_hash_algo_t smw_hash;
	smw_mac_algo_t smw_mac;
	smw_cipher_mode_t smw_cipher_mode;
	smw_signature_algo_t smw_sign_algo;
	smw_signature_type_t smw_sign_type;
	smw_aead_mode_t smw_aead_mode;
	smw_kdf_t smw_kdf;
	smw_attr_algo_t smw_algo_id;
	unsigned int nb_smw_key_types;
	smw_key_type_t *smw_key_types;
};

/**
 * struct mgroup - Definition of a mechanism group
 * @number: Number of mechanisms in the group
 * @mechanism: Mechanism entry
 * @check: Function checking if mechanism supported in SMW
 * @info: Function getting SMW information on mechanism
 * @op: Function executing the mechanism operation
 *
 * Mechanisms are grouped by class of cryptographic
 */
struct mgroup {
	unsigned int number;
	struct mentry *mechanism;

	void (*check)(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
		      struct mgroup *mgroup);
	CK_RV(*info)
	(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type, struct mentry *entry,
	 CK_MECHANISM_INFO_PTR info);
	CK_RV (*op)(CK_SLOT_ID slotid, struct mentry *entry, void *args);
};

/* Macro filling a struct mentry for a single algo */
#define M_ALGO(_key_type_name, _hash_name, _mac_name, _cipher_mode_name,       \
	       _aead_mode_name, _sign_algo_name, _sign_type_name, _kdf_name,   \
	       _algo_id, _id)                                                  \
	{                                                                      \
		.type = CKM_##_id, .slot_flag = 0,                             \
		.smw_key_type = SMW_KEY_TYPE_NAME_##_key_type_name,            \
		.smw_hash = _hash_name, .smw_mac = _mac_name,                  \
		.smw_cipher_mode = _cipher_mode_name,                          \
		.smw_aead_mode = _aead_mode_name,                              \
		.smw_sign_algo = _sign_algo_name,                              \
		.smw_sign_type = _sign_type_name, .smw_kdf = _kdf_name,        \
		.smw_algo_id = _algo_id, .nb_smw_key_types = 0,                \
		.smw_key_types = NULL,                                         \
	}

#define M_DIGEST(_hash, _id)                                                   \
	M_ALGO(NONE, SMW_HASH_ALGO_NAME_##_hash, SMW_MAC_ALGO_NAME_NONE,       \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_NONE, SMW_SIGNATURE_TYPE_NAME_NONE,     \
	       SMW_KDF_NAME_NONE, SMW_ATTR_HASH_##_hash, _id)

/* Macro filling a struct mentry for an algo or a list of algo */
#define M_ECKEYGEN(_key_types, _nb_key_types, _id)                             \
	{                                                                      \
		.type = CKM_##_id, .slot_flag = 0,                             \
		.smw_hash = SMW_HASH_ALGO_NAME_NONE,                           \
		.smw_mac = SMW_MAC_ALGO_NAME_NONE,                             \
		.smw_cipher_mode = SMW_CIPHER_MODE_NAME_NONE,                  \
		.smw_aead_mode = SMW_AEAD_MODE_NAME_NONE,                      \
		.smw_sign_algo = SMW_SIGNATURE_ALGO_NAME_NONE,                 \
		.smw_sign_type = SMW_SIGNATURE_TYPE_NAME_NONE,                 \
		.smw_kdf = SMW_KDF_NAME_NONE, .smw_algo_id = 0,                \
		.nb_smw_key_types = _nb_key_types,                             \
		.smw_key_types = _key_types,                                   \
	}

#define M_KEYGEN(_key_type, _id)                                               \
	{                                                                      \
		.type = CKM_##_id, .slot_flag = 0,                             \
		.smw_key_type = SMW_KEY_TYPE_NAME_##_key_type,                 \
		.smw_hash = SMW_HASH_ALGO_NAME_NONE,                           \
		.smw_mac = SMW_MAC_ALGO_NAME_NONE,                             \
		.smw_cipher_mode = SMW_CIPHER_MODE_NAME_NONE,                  \
		.smw_aead_mode = SMW_AEAD_MODE_NAME_NONE,                      \
		.smw_sign_type = SMW_SIGNATURE_TYPE_NAME_NONE,                 \
		.smw_sign_algo = SMW_SIGNATURE_ALGO_NAME_NONE,                 \
		.smw_kdf = SMW_KDF_NAME_NONE, .smw_algo_id = 0,                \
		.nb_smw_key_types = 1, .smw_key_types = NULL,                  \
	}

#define M_KEYDERIVE(_key_type, _algo_id, _id)                                  \
	{                                                                      \
		.type = CKM_##_id##_DERIVE, .slot_flag = 0,                    \
		.smw_key_type = SMW_KEY_TYPE_NAME_##_key_type,                 \
		.smw_hash = SMW_HASH_ALGO_NAME_NONE,                           \
		.smw_mac = SMW_MAC_ALGO_NAME_NONE,                             \
		.smw_cipher_mode = SMW_CIPHER_MODE_NAME_NONE,                  \
		.smw_aead_mode = SMW_AEAD_MODE_NAME_NONE,                      \
		.smw_sign_type = SMW_SIGNATURE_TYPE_NAME_NONE,                 \
		.smw_sign_algo = SMW_SIGNATURE_ALGO_NAME_NONE,                 \
		.smw_kdf = SMW_KDF_NAME_##_algo_id,                            \
		.smw_algo_id = SMW_ATTR_ALGO_##_algo_id,                       \
		.nb_smw_key_types = 1, .smw_key_types = NULL,                  \
	}

#define M_SIGN_ECDSA_ANY_HASH(_id)                                             \
	M_ALGO(NONE, SMW_HASH_ALGO_NAME_NONE, SMW_MAC_ALGO_NAME_NONE,          \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_ECDSA, SMW_SIGNATURE_TYPE_NAME_NONE,    \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_ANY,    \
							SMW_ATTR_HASH_ANY),    \
	       _id)

#define M_SIGN_ECDSA(_hash, _id)                                               \
	M_ALGO(NONE, SMW_HASH_ALGO_NAME_##_hash, SMW_MAC_ALGO_NAME_NONE,       \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_ECDSA, SMW_SIGNATURE_TYPE_NAME_NONE,    \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(                       \
		       SMW_ATTR_CURVE_ANY, SMW_ATTR_HASH_##_hash),             \
	       _id)

#define M_SIGN_RSA_ANY_HASH(_mode, _id)                                        \
	M_ALGO(NONE, SMW_HASH_ALGO_NAME_NONE, SMW_MAC_ALGO_NAME_NONE,          \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_RSA, SMW_SIGNATURE_TYPE_NAME_##_mode,   \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_##_mode,   \
						      SMW_ATTR_HASH_ANY, 0),   \
	       _id)

#define M_SIGN_RSA(_mode, _hash, _id)                                          \
	M_ALGO(NONE, SMW_HASH_ALGO_NAME_##_hash, SMW_MAC_ALGO_NAME_NONE,       \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_RSA, SMW_SIGNATURE_TYPE_NAME_##_mode,   \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_##_mode,   \
						      SMW_ATTR_HASH_##_hash,   \
						      0),                      \
	       _id)

#define M_CIPHER(_algo, _mode, _mode_id, _id)                                  \
	M_ALGO(_algo, SMW_HASH_ALGO_NAME_NONE, SMW_MAC_ALGO_NAME_NONE,         \
	       SMW_CIPHER_MODE_NAME_##_mode, SMW_AEAD_MODE_NAME_NONE,          \
	       SMW_SIGNATURE_ALGO_NAME_NONE, SMW_SIGNATURE_TYPE_NAME_NONE,     \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_DEFAULT,       \
						  SMW_ATTR_MODE_##_mode_id),   \
	       _id)

#define M_AEAD(_algo, _mode, _mode_id, _id)                                    \
	M_ALGO(_algo, SMW_HASH_ALGO_NAME_NONE, SMW_MAC_ALGO_NAME_NONE,         \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_##_mode,          \
	       SMW_SIGNATURE_ALGO_NAME_NONE, SMW_SIGNATURE_TYPE_NAME_NONE,     \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_AEAD(SMW_ATTR_ALGO_##_algo,                       \
				  SMW_ATTR_MODE_##_mode_id, 0),                \
	       _id)

#define M_MAC(_algo, _mac, _mode_id, _id)                                      \
	M_ALGO(_algo, SMW_HASH_ALGO_NAME_NONE, SMW_MAC_ALGO_NAME_##_mac,       \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_NONE, SMW_SIGNATURE_TYPE_NAME_NONE,     \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_MAC(SMW_ATTR_ALGO_##_algo,                        \
				 SMW_ATTR_MODE_##_mode_id, 0),                 \
	       _id)

#define M_HMAC(_mac, _hash, _id)                                               \
	M_ALGO(HMAC, SMW_HASH_ALGO_NAME_##_hash, SMW_MAC_ALGO_NAME_##_mac,     \
	       SMW_CIPHER_MODE_NAME_NONE, SMW_AEAD_MODE_NAME_NONE,             \
	       SMW_SIGNATURE_ALGO_NAME_NONE, SMW_SIGNATURE_TYPE_NAME_NONE,     \
	       SMW_KDF_NAME_NONE,                                              \
	       SMW_ATTR_ALGO_MAC_HMAC(SMW_ATTR_HASH_##_hash, 0), _id)

/* Macro filling a group of mechanisms */
#define M_GROUP(nb, grp)                                                       \
	{                                                                      \
		.number = nb, .mechanism = grp, .check = check_##grp,          \
		.info = info_##grp, .op = op_##grp,                            \
	}

/*
 * Digest mechanisms
 */
static struct mentry mdigest[] = {
	M_DIGEST(MD5, MD5),	      M_DIGEST(SHA1, SHA_1),
	M_DIGEST(SHA224, SHA224),     M_DIGEST(SHA256, SHA256),
	M_DIGEST(SHA384, SHA384),     M_DIGEST(SHA512, SHA512),
	M_DIGEST(SHA3_224, SHA3_224), M_DIGEST(SHA3_256, SHA3_256),
	M_DIGEST(SHA3_384, SHA3_384), M_DIGEST(SHA3_512, SHA3_512),
};

/*
 * EC Key Generate mechanisms
 */
static struct mentry meckeygen[] = {
	M_ECKEYGEN(smw_ec_name, ARRAY_SIZE(smw_ec_name), EC_KEY_PAIR_GEN),
};

/*
 * Key Generate mechanism
 * Cipher, HMAC and RSA keys
 */
static struct mentry mkeygen[] = {
	M_KEYGEN(AES, AES_KEY_GEN),
	M_KEYGEN(DES, DES_KEY_GEN),
	M_KEYGEN(DES3, DES3_KEY_GEN),
	M_KEYGEN(SM4, SM4_KEY_GEN),
	M_KEYGEN(HMAC, GENERIC_SECRET_KEY_GEN),
	M_KEYGEN(RSA, RSA_PKCS_KEY_PAIR_GEN),
};

/*
 * Key Derive mechanism
 */
static struct mentry mkeyderive[] = { M_KEYDERIVE(HKDF_IKM, HKDF, HKDF) };

/*
 * Signature mechanism
 */
static struct mentry msign_ecdsa[] = {
	M_SIGN_ECDSA_ANY_HASH(ECDSA),	    M_SIGN_ECDSA(SHA1, ECDSA_SHA1),
	M_SIGN_ECDSA(SHA224, ECDSA_SHA224), M_SIGN_ECDSA(SHA256, ECDSA_SHA256),
	M_SIGN_ECDSA(SHA384, ECDSA_SHA384), M_SIGN_ECDSA(SHA512, ECDSA_SHA512),
};

static struct mentry msign_rsa[] = {
	M_SIGN_RSA_ANY_HASH(PKCS1_1_5, RSA_PKCS),
	M_SIGN_RSA(PKCS1_1_5, SHA1, SHA1_RSA_PKCS),
	M_SIGN_RSA(PKCS1_1_5, SHA224, SHA224_RSA_PKCS),
	M_SIGN_RSA(PKCS1_1_5, SHA256, SHA256_RSA_PKCS),
	M_SIGN_RSA(PKCS1_1_5, SHA384, SHA384_RSA_PKCS),
	M_SIGN_RSA(PKCS1_1_5, SHA512, SHA512_RSA_PKCS),
	M_SIGN_RSA_ANY_HASH(PSS, RSA_PKCS_PSS),
	M_SIGN_RSA(PSS, SHA1, SHA1_RSA_PKCS_PSS),
	M_SIGN_RSA(PSS, SHA224, SHA224_RSA_PKCS_PSS),
	M_SIGN_RSA(PSS, SHA256, SHA256_RSA_PKCS_PSS),
	M_SIGN_RSA(PSS, SHA384, SHA384_RSA_PKCS_PSS),
	M_SIGN_RSA(PSS, SHA512, SHA512_RSA_PKCS_PSS),
};

/*
 * Cipher mechanisms
 */
static struct mentry mcipher[] = {
	M_CIPHER(AES, CBC, CBC_NO_PAD, AES_CBC),
	M_CIPHER(AES, CTR, CTR, AES_CTR),
	M_CIPHER(AES, CTS, CTS, AES_CTS),
	M_CIPHER(AES, ECB, ECB_NO_PAD, AES_ECB),
	M_CIPHER(AES, XTS, XTS, AES_XTS),
	M_CIPHER(DES, CBC, CBC_NO_PAD, DES_CBC),
	M_CIPHER(DES, ECB, ECB_NO_PAD, DES_ECB),
	M_CIPHER(DES3, CBC, CBC_NO_PAD, DES3_CBC),
	M_CIPHER(DES3, ECB, ECB_NO_PAD, DES3_ECB),
	M_CIPHER(SM4, CBC, CBC_NO_PAD, SM4_CBC),
	M_CIPHER(SM4, CTR, CTR, SM4_CTR),
	M_CIPHER(SM4, ECB, ECB_NO_PAD, SM4_ECB),
};

static struct mentry maead[] = {
	M_AEAD(AES, GCM, GCM, AES_GCM), M_AEAD(AES, CCM, CCM, AES_CCM),
	M_AEAD(AES, CHACHA20_POLY1305, POLY1305, CHACHA20_POLY1305)
};

/*
 * CMAC mechanisms
 */
static struct mentry mcmac[] = {
	M_MAC(AES, CMAC, CMAC, AES_CMAC),
	M_MAC(DES3, CMAC, CMAC, DES3_CMAC),
	M_MAC(AES, CMAC_TRUNCATED, CMAC, AES_CMAC_GENERAL),
	M_MAC(DES3, CMAC_TRUNCATED, CMAC, DES3_CMAC_GENERAL),
};

/*
 * HMAC mechanisms
 */
static struct mentry mhmac[] = {
	M_HMAC(HMAC, MD5, MD5_HMAC),
	M_HMAC(HMAC, SHA1, SHA_1_HMAC),
	M_HMAC(HMAC, SHA224, SHA224_HMAC),
	M_HMAC(HMAC, SHA256, SHA256_HMAC),
	M_HMAC(HMAC, SHA384, SHA384_HMAC),
	M_HMAC(HMAC, SHA512, SHA512_HMAC),
	M_HMAC(HMAC, SHA3_224, SHA3_224_HMAC),
	M_HMAC(HMAC, SHA3_256, SHA3_256_HMAC),
	M_HMAC(HMAC, SHA3_384, SHA3_384_HMAC),
	M_HMAC(HMAC, SHA3_512, SHA3_512_HMAC),
	M_HMAC(HMAC_TRUNCATED, MD5, MD5_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA1, SHA_1_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA224, SHA224_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA256, SHA256_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA384, SHA384_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA512, SHA512_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA3_224, SHA3_224_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA3_256, SHA3_256_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA3_384, SHA3_384_HMAC_GENERAL),
	M_HMAC(HMAC_TRUNCATED, SHA3_512, SHA3_512_HMAC_GENERAL),
};

/*
 * All SMW mechanisms
 */
static struct mgroup smw_mechanims[] = {
	M_GROUP(ARRAY_SIZE(mdigest), mdigest),
	M_GROUP(ARRAY_SIZE(meckeygen), meckeygen),
	M_GROUP(ARRAY_SIZE(mkeygen), mkeygen),
	M_GROUP(ARRAY_SIZE(mkeyderive), mkeyderive),
	M_GROUP(ARRAY_SIZE(msign_ecdsa), msign_ecdsa),
	M_GROUP(ARRAY_SIZE(msign_rsa), msign_rsa),
	M_GROUP(ARRAY_SIZE(mcipher), mcipher),
	M_GROUP(ARRAY_SIZE(maead), maead),
	M_GROUP(ARRAY_SIZE(mcmac), mcmac),
	M_GROUP(ARRAY_SIZE(mhmac), mhmac),
	{ 0 }
};

static CK_RV find_mechanism(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mgroup **group, struct mentry **entry)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct mgroup *grp = NULL;
	struct mentry *ent = NULL;
	unsigned int idx = 0;
	CK_FLAGS slot_flag = 0;

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

	/* Check if the Slot is present */
	if (!dev->slot.flags & CKF_TOKEN_PRESENT) {
		DBG_TRACE("Slot %lu is not present", slotid);
		return CKR_TOKEN_NOT_PRESENT;
	}

	DBG_TRACE("Search for mechanism 0x%lx", type);

	slot_flag = BIT(slotid);
	for (grp = smw_mechanims; grp->number; grp++) {
		for (idx = 0, ent = grp->mechanism; idx < grp->number;
		     idx++, ent++) {
			if (ent->type == type) {
				DBG_TRACE("Found mechanism 0x%lx", type);
				if (!(ent->slot_flag & slot_flag)) {
					DBG_TRACE("0x%lx not supported", type);
					return CKR_MECHANISM_INVALID;
				}
				if (group)
					*group = grp;
				if (entry)
					*entry = ent;

				return CKR_OK;
			}
		}
	}

	return CKR_MECHANISM_INVALID;
}

static smw_hash_algo_t get_hash_algo(CK_MECHANISM_TYPE mech_type)
{
	smw_hash_algo_t hash_algo = SMW_HASH_ALGO_NAME_NONE;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mdigest); i++) {
		if (mech_type == mdigest[i].type) {
			hash_algo = mdigest[i].smw_hash;
			break;
		}
	}

	return hash_algo;
}

static smw_attr_algo_t get_hash_algo_id(CK_MECHANISM_TYPE mech_type)
{
	smw_attr_algo_t hash_algo_id = SMW_ATTR_HASH_ANY;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mdigest); i++) {
		if (mech_type == mdigest[i].type) {
			hash_algo_id = mdigest[i].smw_algo_id;
			break;
		}
	}

	return hash_algo_id;
}

static smw_kdf_t get_kdf(CK_MECHANISM_TYPE mech_type)
{
	smw_kdf_t kdf = SMW_KDF_NAME_NONE;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mkeyderive); i++) {
		if (mech_type == mkeyderive[i].type) {
			kdf = mkeyderive[i].smw_kdf;
			break;
		}
	}

	return kdf;
}

static CK_RV get_key_permitted_algo(smw_attr_algo_t *permitted_algo,
				    CK_SLOT_ID slotid, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct libmech_list *mech_list = NULL;
	struct mentry *entry = NULL;

	mech_list = get_key_mech_list(obj);

	/* Only one permitted algorithm is supported. */
	if (mech_list->number) {
		ret = find_mechanism(slotid, mech_list->mech[0], NULL, &entry);
		if (ret != CKR_OK) {
			DBG_TRACE("Key allowed mechanism 0x%lx error %ld",
				  mech_list->mech[0], ret);
		} else {
			DBG_TRACE("Key permitted algorithm 0x%" PRIx64,
				  entry->smw_algo_id);
			*permitted_algo = entry->smw_algo_id;
		}
	}

	return ret;
}

static smw_cipher_mode_t get_cipher_mode(CK_MECHANISM_TYPE mech_type)
{
	smw_cipher_mode_t mode = SMW_CIPHER_MODE_NAME_NONE;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mcipher); i++) {
		if (mech_type == mcipher[i].type) {
			mode = mcipher[i].smw_cipher_mode;
			break;
		}
	}

	return mode;
}

static smw_aead_mode_t get_aead_mode(CK_MECHANISM_TYPE mech_type)
{
	smw_aead_mode_t mode = SMW_AEAD_MODE_NAME_NONE;
	unsigned int i = 0;

	for (i = 0; i < ARRAY_SIZE(maead); i++) {
		if (mech_type == maead[i].type) {
			mode = maead[i].smw_aead_mode;
			break;
		}
	}

	return mode;
}

static bool get_aead_mech(smw_attr_algo_t perm_algo, CK_MECHANISM_TYPE *mech)
{
	bool found = false;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(maead); i++) {
		if (perm_algo == maead[i].smw_algo_id) {
			*mech = maead[i].type;
			found = true;
			break;
		}
	}

	DBG_TRACE("%s mechanism (0x%08lX)", found ? "Found" : "No", *mech);

	return found;
}

static bool get_sign_mech(smw_attr_algo_t perm_algo, CK_MECHANISM_TYPE *mech)
{
	bool found = false;
	unsigned int i = 0;
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;

	algo = SMW_ATTR_GET_ALGO(perm_algo);

	if (algo == SMW_ATTR_ALGO_ECDSA) {
		for (; i < ARRAY_SIZE(msign_ecdsa); i++) {
			if (perm_algo == msign_ecdsa[i].smw_algo_id) {
				*mech = msign_ecdsa[i].type;
				found = true;
				break;
			}
		}

	} else if (algo == SMW_ATTR_ALGO_RSA) {
		for (; i < ARRAY_SIZE(msign_rsa); i++) {
			if (perm_algo == msign_rsa[i].smw_algo_id) {
				*mech = msign_rsa[i].type;
				found = true;
				break;
			}
		}
	}

	DBG_TRACE("%s mechanism (0x%08lX)", found ? "Found" : "No", *mech);

	return found;
}

static bool get_mac_mech(smw_attr_algo_t perm_algo, CK_MECHANISM_TYPE *mech)
{
	bool found = false;
	unsigned int i = 0;
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;

	algo = SMW_ATTR_GET_ALGO(perm_algo);

	if (algo == SMW_ATTR_ALGO_HMAC) {
		for (; i < ARRAY_SIZE(mhmac); i++) {
			if (perm_algo == mhmac[i].smw_algo_id) {
				*mech = mhmac[i].type;
				found = true;
				break;
			}
		}
	} else {
		for (; i < ARRAY_SIZE(mcmac); i++) {
			if (perm_algo == mcmac[i].smw_algo_id) {
				*mech = mcmac[i].type;
				found = true;
				break;
			}
		}
	}

	DBG_TRACE("%s mechanism (0x%08lX)", found ? "Found" : "No", *mech);

	return found;
}

static bool get_cipher_mech(smw_attr_algo_t perm_algo, smw_key_type_t smw_key,
			    CK_MECHANISM_TYPE *mech)
{
	bool found = false;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mcipher); i++) {
		if (smw_key == mcipher[i].smw_key_type &&
		    perm_algo == mcipher[i].smw_algo_id) {
			*mech = mcipher[i].type;
			found = true;
			break;
		}
	}

	DBG_TRACE("%s mechanism (0x%08lX)", found ? "Found" : "No", *mech);

	return found;
}

static CK_RV get_key_allowed_algo(struct libobj_obj *obj,
				  struct smw_get_key_attributes_args *attr_args)
{
	CK_RV ret = CKR_OK;
	bool found = false;
	smw_attr_algo_t class = SMW_ATTR_CLASS_NONE;
	CK_MECHANISM_TYPE mech = 0;
	smw_attr_algo_t algo = SMW_ATTR_ALGO_NONE;
	smw_key_type_t smw_key = SMW_KEY_TYPE_NAME_NONE;
	struct libmech_list *mech_list = get_key_mech_list(obj);
	CK_MECHANISM_TYPE key_allowed_mech[1] = { 0 };
	struct CK_ATTRIBUTE mech_attr = { .type = CKA_ALLOWED_MECHANISMS,
					  .pValue = &key_allowed_mech,
					  .ulValueLen =
						  sizeof(key_allowed_mech) };

	algo = attr_args->key_attributes.permitted_algo;
	class = SMW_ATTR_GET_CLASS(algo);
	smw_key = attr_args->key_descriptor->type_name;

	switch (class) {
	case SMW_ATTR_CLASS_AEAD:
		found = get_aead_mech(algo, &mech);
		break;

	case SMW_ATTR_CLASS_ASYMMETRIC_SIGNATURE:
		found = get_sign_mech(algo, &mech);
		break;

	case SMW_ATTR_CLASS_MAC:
		found = get_mac_mech(algo, &mech);
		break;

	case SMW_ATTR_CLASS_SYMMETRIC_ENCRYPTION:
		found = get_cipher_mech(algo, smw_key, &mech);
		break;

	default:
		break;
	}

	if (found) {
		if (mech_list->mech)
			free(mech_list->mech);

		key_allowed_mech[0] = mech;
		ret = attr_to_mech_list(mech_list, &mech_attr);
	}

	return ret;
}

static void check_mdigest(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			  struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		status = smw_config_check_digest(subsystem, entry->smw_hash);
		DBG_TRACE("Subsystem #%d digest #%d: %d", subsystem,
			  entry->smw_hash, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static CK_RV info_mdigest(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	(void)entry;
	CK_RV ret = CKR_OK;

	DBG_TRACE("Return info of 0x%lx digest mechanism", type);

	/*
	 * Digest global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = CKF_DIGEST;

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static CK_RV op_mdigest(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	CK_RV ret = CKR_SLOT_ID_INVALID;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	struct libdig_params *params = args;
	struct smw_hash_args hash_args = { 0 };

	DBG_TRACE("Digest mechanism");
	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return ret;

	hash_args.subsystem_name = devinfo->name;
	hash_args.algo_name = entry->smw_hash;

	hash_args.input = params->pData;
	if (SET_OVERFLOW(params->ulDataLen, hash_args.input_length))
		return CKR_ARGUMENTS_BAD;

	hash_args.output = params->pDigest;
	if (SET_OVERFLOW(*params->pulDigestLen, hash_args.output_length))
		return CKR_ARGUMENTS_BAD;

	status = smw_hash(&hash_args);

	ret = smw_status_to_ck_rv(status);

	if (ret == CKR_OK || ret == CKR_BUFFER_TOO_SMALL)
		*params->pulDigestLen = hash_args.output_length;

	DBG_TRACE("Digest on %d status %d return %ld", devinfo->name, status,
		  ret);
	return ret;
}

static void check_keygen_common(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
				struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;
	smw_key_type_t *key_type = NULL;
	unsigned int entry_idx = 0;
	unsigned int key_type_idx = 0;
	struct smw_key_info info = { 0 };

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; entry_idx < mgroup->number;
	     entry_idx++, entry++) {
		if (entry->nb_smw_key_types > 1)
			key_type = &entry->smw_key_types[0];
		else
			key_type = &entry->smw_key_type;

		for (key_type_idx = 0; key_type_idx < entry->nb_smw_key_types;
		     key_type_idx++) {
			info.key_type_name = *key_type;

			status =
				smw_config_check_generate_key(subsystem, &info);
			DBG_TRACE("Subsystem #%d Key Generate #%d: %d",
				  subsystem, info.key_type_name, status);

			if (status == SMW_STATUS_OK)
				SET_BITS(entry->slot_flag, slot_flag);

			if (entry->nb_smw_key_types > 1)
				key_type++;
		}
	}
}

static void check_meckeygen(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			    struct mgroup *mgroup)
{
	DBG_TRACE("Check EC Key generate");
	check_keygen_common(slotid, subsystem, mgroup);
}

static void check_mkeygen(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			  struct mgroup *mgroup)
{
	DBG_TRACE("Check Key generate");
	check_keygen_common(slotid, subsystem, mgroup);
}

static CK_RV info_keygen_common(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				struct mentry *entry,
				CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	smw_key_type_t *key_type = NULL;
	unsigned int idx = 0;
	struct smw_key_info keyinfo = { 0 };

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	if (entry->nb_smw_key_types > 1)
		key_type = &entry->smw_key_types[0];
	else
		key_type = &entry->smw_key_type;

	for (; idx < entry->nb_smw_key_types; idx++) {
		keyinfo.key_type_name = *key_type;
		keyinfo.security_size = 0;

		status = smw_config_check_generate_key(devinfo->name, &keyinfo);
		DBG_TRACE("Subsystem #%d Key Generate #%d: %d", devinfo->name,
			  keyinfo.key_type_name, status);

		if (status != SMW_STATUS_OK)
			continue;

		info->ulMaxKeySize =
			MAX(info->ulMaxKeySize, keyinfo.security_size_max);

		if (!info->ulMinKeySize)
			info->ulMinKeySize = keyinfo.security_size_min;
		else
			info->ulMinKeySize = MIN(info->ulMinKeySize,
						 keyinfo.security_size_min);

		if (entry->nb_smw_key_types > 1)
			key_type++;
	}

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static CK_RV info_meckeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	DBG_TRACE("Return info of 0x%lx EC Key Generate mechanism", type);

	/*
	 * EC Key Generate global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = CKF_GENERATE_KEY_PAIR | CKF_EC_OID | CKF_EC_CURVENAME |
		      CKF_EC_F_P | CKF_EC_UNCOMPRESS;

	return info_keygen_common(slotid, type, entry, info);
}

static CK_RV info_mkeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	DBG_TRACE("Return info of 0x%lx Key Generate mechanism", type);

	/*
	 * Key Generate global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	if (type == CKM_RSA_PKCS_KEY_PAIR_GEN)
		info->flags = CKF_GENERATE_KEY_PAIR;
	else
		info->flags = CKF_GENERATE;

	return info_keygen_common(slotid, type, entry, info);
}

static CK_RV key_desc_to_smw(CK_SLOT_ID slotid, struct smw_key_descriptor *desc,
			     struct smw_key_attributes *attributes,
			     struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;

	ret = key_desc_setup(desc, obj);
	if (ret != CKR_OK)
		goto end;

	if (attributes) {
		ret = get_key_permitted_algo(&attributes->permitted_algo,
					     slotid, obj);
		if (ret != CKR_OK)
			goto end;

		args_attrs_key_usage(&attributes->usage_flags, obj);
		args_attr_key_storage(&attributes->attributes, obj);
	}

end:
	return ret;
}

static CK_RV op_keygen_common(CK_SLOT_ID slotid, struct libobj_obj *obj)
{
	CK_RV ret = CKR_SLOT_ID_INVALID;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key = { 0 };

	DBG_TRACE("Common Generate Key mechanism");
	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return ret;

	ret = key_desc_to_smw(slotid, &key, &key_attributes, obj);
	if (ret != CKR_OK)
		return ret;

	gen_args.subsystem_name = devinfo->name;
	gen_args.key_descriptor = &key;
	gen_args.key_attributes = &key_attributes;

	status = smw_generate_key(&gen_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Generate Key on subsystem #%d SMW status %d return 0x%lx",
		  devinfo->name, status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

	return ret;
}

static CK_RV op_meckeygen(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	(void)entry;
	DBG_TRACE("Generate EC Key mechanism");
	return op_keygen_common(slotid, args);
}

static CK_RV op_mkeygen(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	(void)entry;
	DBG_TRACE("Generate Key mechanism");
	return op_keygen_common(slotid, args);
}

static void check_mkeyderive(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			     struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;
	unsigned int entry_idx = 0;

	/*
	 * Slot flag is set if:
	 * key derivation using entry->smw_kdf is supported
	 */
	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; entry_idx < mgroup->number;
	     entry_idx++, entry++) {
		status = smw_config_check_derive_key(subsystem, entry->smw_kdf);
		DBG_TRACE("Subsystem # %d KDF : %d status = %d", subsystem,
			  entry->smw_kdf, status);

		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static CK_RV info_mkeyderive(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			     struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL;

	DBG_TRACE("Return info of 0x%lx Key derivation mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	status = smw_config_check_derive_key(devinfo->name, entry->smw_kdf);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_DERIVE;

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static int set_hkdf_args(struct libobj_key_derive_params *derive_params,
			 struct smw_derive_key_args *derive_args)
{
	CK_RV status = CKR_ARGUMENTS_BAD;

	unsigned char **salt = NULL;
	unsigned int *salt_len = NULL;
	unsigned char **info = NULL;
	unsigned int *info_len = NULL;
	struct smw_kdf_hkdf_args *hkdf_args = NULL;

	if (!derive_params || !derive_args)
		return status;

	hkdf_args = derive_args->kdf_arguments;
	hkdf_args->expand = derive_params->hkdf_params.expand;
	hkdf_args->extract = derive_params->hkdf_params.extract;
	hkdf_args->hash_algo =
		get_hash_algo(derive_params->hkdf_params.prf_hash_mech);

	if (hkdf_args->extract && hkdf_args->expand) {
		salt = &hkdf_args->hkdf_args.salt;
		salt_len = &hkdf_args->hkdf_args.salt_len;
		info = &hkdf_args->hkdf_args.info;
		info_len = &hkdf_args->hkdf_args.info_len;
	} else if (hkdf_args->extract && !hkdf_args->expand) {
		salt = &hkdf_args->hkdf_extract_args.salt;
		salt_len = &hkdf_args->hkdf_extract_args.salt_len;
	} else if (!hkdf_args->extract && hkdf_args->expand) {
		info = &hkdf_args->hkdf_expand_args.info;
		info_len = &hkdf_args->hkdf_expand_args.info_len;
	}

	if (hkdf_args->extract) {
		if (derive_params->hkdf_params.salt_type ==
		    CKF_HKDF_SALT_DATA) {
			*salt = derive_params->hkdf_params.salt;

			if (SET_OVERFLOW(derive_params->hkdf_params.salt_len,
					 *salt_len))
				return status;
		}
	}

	if (hkdf_args->expand) {
		*info = derive_params->hkdf_params.info;

		if (SET_OVERFLOW(derive_params->hkdf_params.info_len,
				 *info_len))
			return status;
	}

	status = CKR_OK;

	return status;
}

static CK_RV op_mkeyderive(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	CK_RV ret = CKR_SLOT_ID_INVALID;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_derive_key_args derive_args = { 0 };
	struct smw_key_descriptor base_key = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };
	struct smw_derived_key_descriptor der_key_desc = { 0 };
	struct smw_kdf_hkdf_args hkdf_args = { 0 };
	struct libobj_key_derive_params *derive_params = args;
	struct libobj_obj *obj = derive_params->derived_key;

	if (entry->type == CKM_HKDF_DERIVE) {
		derive_args.kdf_arguments = &hkdf_args;
		ret = set_hkdf_args(derive_params, &derive_args);
		if (ret != CKR_OK)
			return ret;
	}

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return ret;

	base_key.buffer = &keypair_buffer;

	ret = base_key_desc_setup((struct libobj_obj *)derive_params->base_key,
				  &base_key);
	if (ret != CKR_OK)
		return ret;

	ret = derived_key_desc_setup(&der_key_desc, obj);
	if (ret != CKR_OK)
		return ret;

	ret = get_key_permitted_algo(&key_attributes.permitted_algo, slotid,
				     obj);
	if (ret != CKR_OK)
		return ret;

	derive_args.subsystem_name = devinfo->name;
	derive_args.key_descriptor_base = &base_key;
	derive_args.key_descriptor_derived = &der_key_desc;
	derive_args.kdf_name = get_kdf(entry->type);
	derive_args.store_derived_key = true;

	args_attrs_key_usage(&key_attributes.usage_flags, obj);
	args_attr_key_storage(&key_attributes.attributes, obj);
	derive_args.key_attributes = &key_attributes;

	status = smw_derive_key(&derive_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Derive Key on subsystem #%d status %d return %ld",
		  devinfo->name, status, ret);

	if (ret == CKR_OK) {
		DBG_TRACE("Derive Key ID = #%d", der_key_desc.id);
		derived_key_desc_copy_key_id(obj, &der_key_desc);
	}

	return ret;
}

static void check_msign_common(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			       struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	struct mentry *entry = NULL;
	struct smw_signature_info info = { 0 };
	CK_FLAGS slot_flag = 0;

	/*
	 * smw_config_check_sign() check:
	 * - the sign algorithm,
	 * - the hash algorithm (optional) and
	 * - the signature type (optional).
	 *
	 * Slot flag is set if:
	 *  - sign or verify or both operations are supported
	 */

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		info.algo_name = entry->smw_sign_algo;
		info.type_name = entry->smw_sign_type;
		info.hash_algo_name = entry->smw_hash;

		status = smw_config_check_sign(subsystem, &info);
		DBG_TRACE("Subsystem #%d sign mechanism %lu: %d", subsystem,
			  entry->type, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);

		status = smw_config_check_verify(subsystem, &info);
		DBG_TRACE("Subsystem #%d verify mechanism %lu: %d", subsystem,
			  entry->type, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static void check_msign_ecdsa(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			      struct mgroup *mgroup)
{
	DBG_TRACE("Check ECDSA Signature mechanism");

	check_msign_common(slotid, subsystem, mgroup);
}

static void check_msign_rsa(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			    struct mgroup *mgroup)
{
	DBG_TRACE("Check RSA Signature mechanism");

	check_msign_common(slotid, subsystem, mgroup);
}

static CK_RV info_msign_common(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			       struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL;
	struct smw_signature_info sign_verify_info = { 0 };

	DBG_TRACE("Return info of 0x%lx signature mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Signature global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	sign_verify_info.algo_name = entry->smw_sign_algo;
	sign_verify_info.type_name = entry->smw_sign_type;
	sign_verify_info.hash_algo_name = entry->smw_hash;

	/* @info flag is set with Sign flag or Verify flag or both */
	status = smw_config_check_sign(devinfo->name, &sign_verify_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_SIGN | CKF_MESSAGE_SIGN;

	status = smw_config_check_verify(devinfo->name, &sign_verify_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_VERIFY | CKF_MESSAGE_VERIFY;

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static CK_RV info_msign_ecdsa(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	return info_msign_common(slotid, type, entry, info);
}

static CK_RV info_msign_rsa(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	return info_msign_common(slotid, type, entry, info);
}

static CK_RV sign(struct lib_signature_params *params,
		  smw_subsystem_t subsystem_name,
		  struct smw_key_descriptor *key_desc,
		  smw_attr_algo_t sign_algo, smw_hash_algo_t hash_algo,
		  unsigned char *input, unsigned int input_length,
		  unsigned char *output, unsigned int output_length)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_context_args op_ctx_args = { 0 };
	struct smw_sign_verify_args smw_sign_verify_args = { 0 };
	struct smw_hash_init_args smw_hash_init_args = { 0 };
	struct smw_hash_update_args smw_hash_update_args = { 0 };
	struct smw_hash_final_args smw_hash_final_args = { 0 };

	struct lib_signature_ctx *ctx = params->ctx;

	switch (params->state) {
	case OP_ONE_SHOT:
		smw_sign_verify_args.subsystem_name = subsystem_name;
		smw_sign_verify_args.key_descriptor = key_desc;
		smw_sign_verify_args.sign_algo = sign_algo;
		smw_sign_verify_args.message = input;
		smw_sign_verify_args.message_length = input_length;
		smw_sign_verify_args.signature = output;
		smw_sign_verify_args.signature_length = output_length;

		if (params->op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN)) {
			status = smw_sign(&smw_sign_verify_args);

			/* Update signature length */
			if (status == SMW_STATUS_OK ||
			    status == SMW_STATUS_OUTPUT_TOO_SHORT)
				params->ulsignaturelen =
					smw_sign_verify_args.signature_length;
		} else {
			status = smw_verify(&smw_sign_verify_args);
		}

		break;

	case OP_UPDATE:
	case OP_NEXT:
		if (ctx->current_state == OP_INIT ||
		    ctx->current_state == OP_BEGIN) {
			op_ctx_args.subsystem_name = subsystem_name;
			status = smw_allocate_context(&op_ctx_args);
			if (status != SMW_STATUS_OK)
				goto end;

			ctx->context = op_ctx_args.context;

			smw_hash_init_args.context = op_ctx_args.context;
			smw_hash_init_args.algo_name = hash_algo;
			smw_hash_init_args.input = input;
			smw_hash_init_args.input_length = input_length;

			status = smw_hash_init(&smw_hash_init_args);
			if (status == SMW_STATUS_OK)
				ctx->context = smw_hash_init_args.context;
		} else if (ctx->current_state == OP_UPDATE ||
			   ctx->current_state == OP_NEXT) {
			smw_hash_update_args.context = ctx->context;
			smw_hash_update_args.input = input;
			smw_hash_update_args.input_length = input_length;

			status = smw_hash_update(&smw_hash_update_args);
			if (status == SMW_STATUS_OK)
				ctx->context = smw_hash_update_args.context;
		}

		break;

	case OP_FINAL:
	case OP_END:
		if (ctx->context) {
			if (params->op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN)) {
				smw_sign_verify_args.subsystem_name =
					subsystem_name;
				smw_sign_verify_args.key_descriptor = key_desc;
				smw_sign_verify_args.sign_algo = sign_algo;
				smw_sign_verify_args.message = NULL;
				smw_sign_verify_args.message_length = 0;
				smw_sign_verify_args.signature = NULL;
				smw_sign_verify_args.signature_length = 0;

				status = smw_sign(&smw_sign_verify_args);
				if (status != SMW_STATUS_OK)
					goto end;

				if (!params->psignature ||
				    output_length < smw_sign_verify_args
							    .signature_length) {
					if (params->psignature)
						status =
							SMW_STATUS_OUTPUT_TOO_SHORT;

					params->ulsignaturelen =
						smw_sign_verify_args
							.signature_length;
					goto end;
				}
			}

			smw_hash_final_args.context = ctx->context;
			status = smw_hash_final(&smw_hash_final_args);
			ctx->context = smw_hash_final_args.context;
			if (status != SMW_STATUS_OK &&
			    status != SMW_STATUS_OUTPUT_TOO_SHORT)
				goto end;

			smw_hash_final_args.output =
				malloc(smw_hash_final_args.output_length);
			if (!smw_hash_final_args.output) {
				status = SMW_STATUS_ALLOC_FAILURE;
				goto end;
			}

			smw_hash_final_args.input = input;
			smw_hash_final_args.input_length = input_length;
			status = smw_hash_final(&smw_hash_final_args);
			ctx->context = smw_hash_final_args.context;
			if (status != SMW_STATUS_OK)
				goto end;

			sign_algo = SMW_ATTR_SET_HASH(sign_algo,
						      SMW_ATTR_HASH_NONE);

			smw_sign_verify_args.message =
				smw_hash_final_args.output;
			smw_sign_verify_args.message_length =
				smw_hash_final_args.output_length;
		} else {
			smw_sign_verify_args.message = input;
			smw_sign_verify_args.message_length = input_length;
		}

		smw_sign_verify_args.subsystem_name = subsystem_name;
		smw_sign_verify_args.key_descriptor = key_desc;
		smw_sign_verify_args.sign_algo = sign_algo;
		smw_sign_verify_args.signature = output;
		smw_sign_verify_args.signature_length = output_length;

		if (params->op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN)) {
			status = smw_sign(&smw_sign_verify_args);

			/* Update signature length */
			if (status == SMW_STATUS_OK ||
			    status == SMW_STATUS_OUTPUT_TOO_SHORT)
				params->ulsignaturelen =
					smw_sign_verify_args.signature_length;
		} else {
			status = smw_verify(&smw_sign_verify_args);
		}

		break;

	default:
		break;
	}

end:
	if (smw_hash_final_args.output)
		free(smw_hash_final_args.output);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("%s on subsystem #%d SMW status %d return 0x%lx",
		  params->op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN) ? "Sign" :
								    "Verify",
		  subsystem_name, status, ret);

	return ret;
}

static CK_RV op_msign_common(CK_SLOT_ID slotid, struct mentry *entry,
			     struct lib_signature_params *params,
			     unsigned int key_id)
{
	const struct libdev *devinfo = NULL;
	struct lib_signature_ctx *ctx = params->ctx;
	smw_subsystem_t subsystem_name = SMW_SUBSYSTEM_NAME_NONE;
	struct smw_key_descriptor key_desc = { 0 };
	smw_attr_algo_t sign_algo = 0;
	smw_hash_algo_t hash_algo = SMW_HASH_ALGO_NAME_NONE;
	unsigned char *input = NULL;
	unsigned int input_length = 0;
	unsigned char *output = NULL;
	unsigned int output_length = 0;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	key_desc.id = key_id;

	subsystem_name = devinfo->name;
	sign_algo = entry->smw_algo_id;

	if (entry->smw_hash == SMW_HASH_ALGO_NAME_NONE) {
		hash_algo = get_hash_algo(ctx->hash_mech);
		sign_algo = SMW_ATTR_SET_HASH(sign_algo,
					      get_hash_algo_id(ctx->hash_mech));
	} else {
		hash_algo = entry->smw_hash;
	}

	if ((ctx->current_state == OP_BEGIN && params->state == OP_NEXT) ||
	    (ctx->current_state == OP_INIT && params->state == OP_UPDATE)) {
		if (hash_algo == SMW_HASH_ALGO_NAME_NONE)
			return CKR_ARGUMENTS_BAD;
	}

	if (ctx->salt_len) {
		if (SET_OVERFLOW(SMW_ATTR_SET_SALT_LENGTH(sign_algo,
							  ctx->salt_len),
				 sign_algo))
			return CKR_ARGUMENTS_BAD;
	}

	if (ctx->mac_len) {
		if (params->ulsignaturelen) {
			if (params->ulsignaturelen < ctx->mac_len)
				return CKR_BUFFER_TOO_SMALL;

			params->ulsignaturelen = ctx->mac_len;
		}
	}

	input = params->pdata;
	output = params->psignature;

	if (SET_OVERFLOW(params->uldatalen, input_length))
		return CKR_DATA_LEN_RANGE;

	if (SET_OVERFLOW(params->ulsignaturelen, output_length))
		return CKR_SIGNATURE_LEN_RANGE;

	return sign(params, subsystem_name, &key_desc, sign_algo, hash_algo,
		    input, input_length, output, output_length);
}

static CK_RV op_msign_ecdsa(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	struct lib_signature_ctx *ctx = NULL;
	unsigned int key_id = 0;

	DBG_TRACE("ECDSA Signature mechanism");

	ctx = ((struct lib_signature_params *)args)->ctx;

	key_id = get_key_id_from((struct libobj_obj *)ctx->hkey, ec_pair);

	return op_msign_common(slotid, entry, args, key_id);
}

static CK_RV op_msign_rsa(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	struct lib_signature_ctx *ctx = NULL;
	unsigned int key_id = 0;

	DBG_TRACE("RSA Signature mechanism");

	ctx = ((struct lib_signature_params *)args)->ctx;

	key_id = get_key_id_from((struct libobj_obj *)ctx->hkey, rsa_pair);

	return op_msign_common(slotid, entry, args, key_id);
}

static void check_mcipher(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			  struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx;
	CK_FLAGS slot_flag = 0;
	struct mentry *entry = NULL;
	struct smw_cipher_info info = { 0 };

	/*
	 * Slot flag is set if:
	 * encryption or decryption operation is supported
	 */

	slot_flag = BIT(slotid);

	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		info.key_type_name = entry->smw_key_type;
		info.mode_name = entry->smw_cipher_mode;
		info.op_type_name = SMW_CIPHER_OP_TYPE_NAME_ENCRYPT;
		status = smw_config_check_cipher(subsystem, &info);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);

		info.op_type_name = SMW_CIPHER_OP_TYPE_NAME_DECRYPT;
		status = smw_config_check_cipher(subsystem, &info);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static CK_RV info_mcipher(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL;
	struct smw_cipher_info cipher_info = { 0 };

	DBG_TRACE("Return info of 0x%lx cipher mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	cipher_info.key_type_name = entry->smw_key_type;
	cipher_info.mode_name = entry->smw_cipher_mode;

	cipher_info.op_type_name = SMW_CIPHER_OP_TYPE_NAME_ENCRYPT;
	status = smw_config_check_cipher(devinfo->name, &cipher_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT;

	cipher_info.op_type_name = SMW_CIPHER_OP_TYPE_NAME_DECRYPT;
	status = smw_config_check_cipher(devinfo->name, &cipher_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_DECRYPT | CKF_MESSAGE_DECRYPT;

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static CK_RV cipher(struct lib_cipher_params *params,
		    struct smw_cipher_init_args *smw_init_args,
		    struct smw_cipher_data_args *smw_data_args)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_cipher_args smw_args = { 0 };
	struct smw_context_args op_ctx_args = { 0 };

	struct lib_cipher_ctx *ctx = NULL;

	ctx = params->ctx;

	smw_args.data = *smw_data_args;
	smw_args.init = *smw_init_args;

	switch (params->state) {
	case OP_ONE_SHOT:
		status = smw_cipher(&smw_args);
		break;

	case OP_NEXT:
		if (ctx->current_state == OP_BEGIN) {
			op_ctx_args.subsystem_name =
				smw_args.init.subsystem_name;
			status = smw_allocate_context(&op_ctx_args);
			if (status != SMW_STATUS_OK)
				goto end;

			smw_init_args->context = op_ctx_args.context;

			status = smw_cipher_init(smw_init_args);
			if (status == SMW_STATUS_OK) {
				ctx->context = smw_init_args->context;
				smw_data_args->context = smw_init_args->context;
				status = smw_cipher_update(smw_data_args);
				ctx->context = smw_data_args->context;
			}

		} else if (ctx->current_state == OP_NEXT) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_cipher_update(smw_data_args);
			ctx->context = smw_data_args->context;
		}

		break;

	case OP_UPDATE:
		if (ctx->current_state == OP_INIT) {
			op_ctx_args.subsystem_name =
				smw_args.init.subsystem_name;
			status = smw_allocate_context(&op_ctx_args);
			if (status != SMW_STATUS_OK)
				goto end;

			smw_init_args->context = op_ctx_args.context;

			status = smw_cipher_init(smw_init_args);
			if (status == SMW_STATUS_OK) {
				ctx->context = smw_init_args->context;
				smw_data_args->context = smw_init_args->context;
				status = smw_cipher_update(smw_data_args);
				ctx->context = smw_data_args->context;
			}

		} else if (ctx->current_state == OP_UPDATE) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_cipher_update(smw_data_args);
			ctx->context = smw_data_args->context;
		}

		break;

	case OP_END:
	case OP_FINAL:
		if (ctx->context) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_cipher_final(smw_data_args);
			ctx->context = smw_data_args->context;
		} else {
			status = SMW_STATUS_OK;
			params->output_length = 0;
			goto end;
		}

		break;

	default:
		break;
	}

	if (status == SMW_STATUS_OK || status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		/* Update output data buffer length */
		if (params->state == OP_ONE_SHOT)
			params->output_length = smw_args.data.output_length;
		else
			params->output_length = smw_data_args->output_length;
	}

end:

	ret = smw_status_to_ck_rv(status);
	DBG_TRACE("%s on subsystem #%d SMW status = 0x%x return = 0x%lx",
		  params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT) ?
			  "ENCRYPT" :
			  "DECRYPT",
		  smw_init_args->subsystem_name, status, ret);
	return ret;
}

static CK_RV set_smw_init_args(struct lib_cipher_ctx *ctx,
			       struct smw_cipher_init_args *smw_init_args,
			       struct smw_keypair_buffer **key_buffer,
			       struct smw_key_descriptor ***keys_desc,
			       struct smw_key_descriptor *key_desc_ptr,
			       smw_subsystem_t subsystem_name, CK_FLAGS op_flag)
{
	CK_RV ret = CKR_HOST_MEMORY;

	unsigned int i = 0;
	unsigned int key_length = 0;
	bool is_xts = false;

	if (ctx->cipher_mech == CKM_AES_XTS) {
		is_xts = true;
		smw_init_args->nb_keys = 2;
		*key_buffer =
			calloc(smw_init_args->nb_keys, sizeof(**key_buffer));
		if (!*key_buffer)
			return ret;

	} else {
		smw_init_args->nb_keys = 1;
	}

	if (is_xts) {
		if (SET_OVERFLOW(ctx->key_len / 2, key_length))
			return CKR_ARGUMENTS_BAD;

		(*key_buffer)[0].gen.private_data = &ctx->key_value[0];
		(*key_buffer)[1].gen.private_data = &ctx->key_value[key_length];

		for (; i < smw_init_args->nb_keys; i++) {
			(*key_buffer)[i].gen.private_length = key_length;
			key_desc_ptr[i].buffer = &(*key_buffer)[i];
			key_desc_ptr[i].type_name = SMW_KEY_TYPE_NAME_AES;
			key_desc_ptr[i].security_size =
				BYTES_TO_BITS(key_length);
		}

	} else {
		key_desc_ptr[0].id =
			get_key_id_from((struct libobj_obj *)ctx->hkey, cipher);
	}

	for (i = 0; i < smw_init_args->nb_keys; i++)
		(*keys_desc)[i] = &key_desc_ptr[i];

	smw_init_args->keys_desc = *keys_desc;
	smw_init_args->subsystem_name = subsystem_name;
	smw_init_args->mode_name = get_cipher_mode(ctx->cipher_mech);
	smw_init_args->iv = ctx->iv;

	if (SET_OVERFLOW(ctx->iv_length, smw_init_args->iv_length))
		return CKR_ARGUMENTS_BAD;

	DBG_TRACE("Cipher mode #%d", smw_init_args->mode_name);

	if (op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
		smw_init_args->op_type_name = SMW_CIPHER_OP_TYPE_NAME_ENCRYPT;
	else
		smw_init_args->op_type_name = SMW_CIPHER_OP_TYPE_NAME_DECRYPT;

	return CKR_OK;
}

static CK_RV op_mcipher(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	(void)entry;
	CK_RV ret = CKR_OK;

	const struct libdev *devinfo = NULL;
	struct lib_cipher_ctx *ctx = NULL;
	struct lib_cipher_params *params = NULL;

	struct smw_keypair_buffer *key_buffer = NULL;
	struct smw_cipher_init_args smw_init_args = { 0 };
	struct smw_cipher_init_args *smw_init_args_ptr = NULL;
	struct smw_cipher_data_args smw_data_args = { 0 };
	struct smw_key_descriptor *keys_desc[2] = { NULL };
	struct smw_key_descriptor key_descriptor[2] = { 0 };
	struct smw_key_descriptor **keys_desc_ptr = NULL;

	keys_desc_ptr = keys_desc;
	smw_init_args_ptr = &smw_init_args;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = (struct lib_cipher_params *)args;
	ctx = params->ctx;

	if (params->state == OP_ONE_SHOT ||
	    (ctx->current_state == OP_INIT && params->state == OP_UPDATE) ||
	    (ctx->current_state == OP_BEGIN &&
	     (params->state == OP_NEXT || params->state == OP_END))) {
		if (set_smw_init_args(ctx, smw_init_args_ptr, &key_buffer,
				      &keys_desc_ptr, &key_descriptor[0],
				      devinfo->name, params->op_flag) != CKR_OK)
			goto end;
	}

	if (SET_OVERFLOW(params->input_length, smw_data_args.input_length)) {
		if (params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
			ret = CKR_DATA_LEN_RANGE;
		else
			ret = CKR_ENCRYPTED_DATA_LEN_RANGE;

		goto end;
	}

	if (SET_OVERFLOW(params->output_length, smw_data_args.output_length)) {
		if (params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
			ret = CKR_ENCRYPTED_DATA_LEN_RANGE;
		else
			ret = CKR_DATA_LEN_RANGE;

		goto end;
	}

	smw_data_args.input = params->pinput;
	smw_data_args.output = params->poutput;
	ret = cipher(params, &smw_init_args, &smw_data_args);

end:
	if (key_buffer)
		free(key_buffer);

	return ret;
}

static CK_RV info_maead(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL;
	struct smw_aead_info aead_info = { 0 };

	DBG_TRACE("Return info of 0x%lx AEAD mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	aead_info.key_type_name = entry->smw_key_type;
	aead_info.mode_name = entry->smw_aead_mode;

	aead_info.op_type_name = SMW_AEAD_OP_TYPE_NAME_ENCRYPT;
	status = smw_config_check_aead(devinfo->name, &aead_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT;

	aead_info.op_type_name = SMW_AEAD_OP_TYPE_NAME_DECRYPT;
	status = smw_config_check_aead(devinfo->name, &aead_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_DECRYPT | CKF_MESSAGE_DECRYPT;

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static void check_maead(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx;
	CK_FLAGS slot_flag = 0;
	struct mentry *entry = NULL;
	struct smw_aead_info info = { 0 };

	/*
	 * Slot flag is set if:
	 * encryption or decryption operation is supported
	 */

	DBG_TRACE("Check AEAD mechanism");

	slot_flag = BIT(slotid);

	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		info.key_type_name = entry->smw_key_type;
		info.mode_name = entry->smw_aead_mode;

		info.op_type_name = SMW_AEAD_OP_TYPE_NAME_ENCRYPT;
		DBG_TRACE("Subsystem #%d AEAD mechanism %lu encrypt: %d",
			  subsystem, entry->type, status);

		status = smw_config_check_aead(subsystem, &info);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);

		info.op_type_name = SMW_AEAD_OP_TYPE_NAME_DECRYPT;
		DBG_TRACE("Subsystem #%d AEAD mechanism %lu decrypt: %d",
			  subsystem, entry->type, status);

		status = smw_config_check_aead(subsystem, &info);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static CK_RV aead(struct lib_cipher_params *params,
		  struct smw_aead_init_args *smw_init_args,
		  struct smw_aead_aad_args *smw_aad_args,
		  struct smw_aead_data_args *smw_data_args,
		  struct smw_aead_final_args *smw_final_args)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_aead_args smw_args = { 0 };
	struct smw_context_args op_ctx_args = { 0 };

	struct lib_cipher_ctx *ctx = NULL;

	ctx = params->ctx;

	smw_args.final = smw_final_args;
	smw_args.init = smw_init_args;
	smw_args.aad = smw_aad_args;

	switch (params->state) {
	case OP_ONE_SHOT:
		status = smw_aead(&smw_args);
		if (status == SMW_STATUS_OK) {
			if (params->op_flag &
			    (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
				ctx->iv_length =
					smw_final_args->output_iv_length;
			ctx->tag = smw_final_args->tag;
			ctx->tag_length = smw_final_args->tag_length;
		}
		break;

	case OP_NEXT:
		if (ctx->current_state == OP_BEGIN) {
			op_ctx_args.subsystem_name =
				smw_args.init->subsystem_name;
			status = smw_allocate_context(&op_ctx_args);
			if (status != SMW_STATUS_OK)
				goto end;

			smw_init_args->context = op_ctx_args.context;

			status = smw_aead_init(smw_init_args);
			if (status == SMW_STATUS_OK &&
			    smw_aad_args->data_length) {
				/*
				 * before the first update operation, we need to
				 * update AAD if there is some.
				 */
				ctx->context = smw_init_args->context;
				smw_aad_args->context = smw_init_args->context;
				status = smw_aead_update_aad(smw_aad_args);
				/*
				 * update the operation context
				 * as it is release in case of error
				 */
				ctx->context = smw_aad_args->context;
			}

			if (status == SMW_STATUS_OK) {
				ctx->context = smw_init_args->context;
				smw_data_args->context = smw_init_args->context;
				status = smw_aead_update(smw_data_args);
				/*
				 * update the operation context
				 * as it is release in case of error
				 */
				ctx->context = smw_data_args->context;
			}
		} else if (ctx->current_state == OP_NEXT) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_aead_update(smw_data_args);
			/*
			 * update the operation context
			 * as it is release in case of error
			 */
			ctx->context = smw_data_args->context;
		}

		break;

	case OP_UPDATE:
		if (ctx->current_state == OP_INIT) {
			op_ctx_args.subsystem_name =
				smw_args.init->subsystem_name;
			status = smw_allocate_context(&op_ctx_args);
			if (status != SMW_STATUS_OK)
				goto end;

			smw_init_args->context = op_ctx_args.context;

			status = smw_aead_init(smw_init_args);
			if (status == SMW_STATUS_OK &&
			    smw_aad_args->data_length) {
				/*
				 * before the first update operation, we need to
				 * update AAD if there is some.
				 */
				ctx->context = smw_init_args->context;
				smw_aad_args->context = smw_init_args->context;
				status = smw_aead_update_aad(smw_aad_args);
				/*
				 * update the operation context
				 * as it is release in case of error
				 */
				ctx->context = smw_aad_args->context;
			}

			if (status == SMW_STATUS_OK) {
				ctx->context = smw_init_args->context;
				smw_data_args->context = smw_init_args->context;
				status = smw_aead_update(smw_data_args);
				/*
				 * update the operation context
				 * as it is release in case of error
				 */
				ctx->context = smw_data_args->context;
			}

		} else if (ctx->current_state == OP_UPDATE) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_aead_update(smw_data_args);
			/*
			 * update the operation context
			 * as it is release in case of error
			 */
			ctx->context = smw_data_args->context;
		}

		break;

	case OP_END:
	case OP_FINAL:
		if (ctx->context) {
			smw_final_args->data->context =
				(struct smw_op_context *)ctx->context;
			status = smw_aead_final(smw_final_args);
			/*
			 * update the operation context
			 * as it is release in case of error
			 */
			ctx->context = smw_final_args->data->context;
			if (status == SMW_STATUS_OK) {
				if (params->op_flag &
				    (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
					ctx->iv_length =
						smw_final_args->output_iv_length;
				ctx->tag = smw_final_args->tag;
				ctx->tag_length = smw_final_args->tag_length;
			}

		} else {
			status = SMW_STATUS_OK;
			params->output_length = 0;
			goto end;
		}

		break;

	default:
		break;
	}

	if (status == SMW_STATUS_OK || status == SMW_STATUS_OUTPUT_TOO_SHORT) {
		/* Update output data buffer length */
		if (params->state != OP_UPDATE && params->state != OP_NEXT)
			params->output_length =
				smw_args.final->data->output_length;
		else
			params->output_length = smw_data_args->output_length;
	}

end:

	ret = smw_status_to_ck_rv(status);
	DBG_TRACE("%s on subsystem #%d SMW status = 0x%x return = 0x%lx",
		  params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT) ?
			  "ENCRYPT" :
			  "DECRYPT",
		  smw_init_args->subsystem_name, status, ret);
	return ret;
}

static CK_RV op_maead(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	(void)entry;
	CK_RV ret = CKR_OK;

	const struct libdev *devinfo = NULL;
	struct lib_cipher_ctx *ctx = NULL;
	struct lib_cipher_params *params = NULL;

	struct smw_aead_init_args smw_init_args = { 0 };
	struct smw_aead_aad_args smw_aad_args = { 0 };
	struct smw_aead_data_args smw_data_args = { 0 };
	struct smw_aead_final_args smw_final_args = { 0 };
	struct smw_key_descriptor key_descriptor = { 0 };

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = (struct lib_cipher_params *)args;
	ctx = params->ctx;

	if (params->state == OP_ONE_SHOT ||
	    (ctx->current_state == OP_INIT && params->state == OP_UPDATE) ||
	    (ctx->current_state == OP_BEGIN &&
	     (params->state == OP_NEXT || params->state == OP_END))) {
		key_descriptor.id =
			get_key_id_from((struct libobj_obj *)ctx->hkey, cipher);

		smw_init_args.key_desc = &key_descriptor;
		smw_init_args.subsystem_name = devinfo->name;
		smw_init_args.mode_name = get_aead_mode(ctx->cipher_mech);
		smw_init_args.user_iv = ctx->iv;

		if (SET_OVERFLOW(ctx->fixed_iv_length,
				 smw_init_args.user_iv_length))
			return CKR_ARGUMENTS_BAD;

		if (SET_OVERFLOW(ctx->iv_length, smw_init_args.iv_length))
			return CKR_ARGUMENTS_BAD;

		if (SET_OVERFLOW(ctx->aad_length, smw_init_args.aad_length))
			return CKR_ARGUMENTS_BAD;

		if (SET_OVERFLOW(ctx->tag_length, smw_init_args.tag_length))
			return CKR_ARGUMENTS_BAD;

		if (SET_OVERFLOW(ctx->payload_length,
				 smw_init_args.plaintext_length))
			return CKR_ARGUMENTS_BAD;

		smw_aad_args.data = ctx->aad;

		if (SET_OVERFLOW(ctx->aad_length, smw_aad_args.data_length))
			return CKR_ARGUMENTS_BAD;

		DBG_TRACE("AEAD mode #%d", smw_init_args.mode_name);

		if (params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
			smw_init_args.op_type_name =
				SMW_AEAD_OP_TYPE_NAME_ENCRYPT;
		else
			smw_init_args.op_type_name =
				SMW_AEAD_OP_TYPE_NAME_DECRYPT;
	}

	if (params->state == OP_FINAL || params->state == OP_END ||
	    params->state == OP_ONE_SHOT) {
		smw_final_args.data = &smw_data_args;

		if (ctx->tag)
			smw_final_args.tag = ctx->tag;

		if (SET_OVERFLOW(ctx->tag_length, smw_final_args.tag_length))
			return CKR_ARGUMENTS_BAD;

		if (params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT)) {
			smw_final_args.op_type_name =
				SMW_AEAD_OP_TYPE_NAME_ENCRYPT;

			smw_final_args.output_iv = ctx->iv;
			if (SET_OVERFLOW(ctx->iv_length,
					 smw_final_args.output_iv_length))
				return CKR_ARGUMENTS_BAD;
		} else {
			smw_final_args.op_type_name =
				SMW_AEAD_OP_TYPE_NAME_DECRYPT;
		}
	}

	if (SET_OVERFLOW(params->input_length, smw_data_args.input_length)) {
		if (params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
			ret = CKR_DATA_LEN_RANGE;
		else
			ret = CKR_ENCRYPTED_DATA_LEN_RANGE;

		goto end;
	}

	if (SET_OVERFLOW(params->output_length, smw_data_args.output_length)) {
		if (params->op_flag & (CKF_ENCRYPT | CKF_MESSAGE_ENCRYPT))
			ret = CKR_ENCRYPTED_DATA_LEN_RANGE;
		else
			ret = CKR_DATA_LEN_RANGE;

		goto end;
	}

	smw_data_args.input = params->pinput;
	smw_data_args.output = params->poutput;
	ret = aead(params, &smw_init_args, &smw_aad_args, &smw_data_args,
		   &smw_final_args);

end:

	return ret;
}

static void check_mmac(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
		       struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	CK_FLAGS slot_flag = 0;
	struct mentry *entry = NULL;
	struct smw_mac_info info = { 0 };

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		info.key_type_name = entry->smw_key_type;
		info.mac_algo_name = entry->smw_mac;
		info.hash_algo_name = entry->smw_hash;

		status = smw_config_check_mac(subsystem, &info);
		DBG_TRACE("Subsystem #%d MAC mechanism %lu: %d", subsystem,
			  entry->type, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static CK_RV info_mmac_common(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL;
	struct smw_mac_info mac_info = { 0 };

	DBG_TRACE("Return info of 0x%lx MAC mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	mac_info.key_type_name = entry->smw_key_type;
	mac_info.mac_algo_name = entry->smw_mac;
	mac_info.hash_algo_name = entry->smw_hash;

	status = smw_config_check_mac(devinfo->name, &mac_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_SIGN | CKF_MESSAGE_SIGN | CKF_VERIFY |
			       CKF_MESSAGE_VERIFY;

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static CK_RV op_mmac_common(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	struct lib_signature_ctx *ctx = NULL;
	struct lib_signature_params *params = NULL;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_mac_args smw_args = { 0 };

	DBG_TRACE("MAC mechanism");

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = args;
	ctx = params->ctx;

	if (params->state != OP_ONE_SHOT &&
	    (ctx->context || params->state != OP_END))
		return ret;

	key_desc.id = get_key_id_from((struct libobj_obj *)ctx->hkey, cipher);

	smw_args.subsystem_name = devinfo->name;
	smw_args.key_descriptor = &key_desc;

	smw_args.input = params->pdata;
	if (SET_OVERFLOW(params->uldatalen, smw_args.input_length))
		return ret;

	smw_args.mac = params->psignature;
	if (SET_OVERFLOW(params->ulsignaturelen, smw_args.mac_length))
		return ret;

	smw_args.algo_name = entry->smw_mac;

	/* Get hash algorithm */
	if (entry->smw_hash != SMW_HASH_ALGO_NAME_NONE)
		smw_args.hash_name = entry->smw_hash;
	else if (ctx->hash_mech)
		smw_args.hash_name = get_hash_algo(ctx->hash_mech);

	if (params->op_flag & (CKF_SIGN | CKF_MESSAGE_SIGN)) {
		status = smw_mac(&smw_args);

		/* Update MAC length */
		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			params->ulsignaturelen = smw_args.mac_length;
	} else {
		status = smw_mac_verify(&smw_args);
	}

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("%s on subsystem #%d SMW status %d return 0x%lx",
		  params->op_flag == CKF_SIGN ? "Sign" : "Verify",
		  smw_args.subsystem_name, status, ret);

	return ret;
}

static void check_mcmac(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup)
{
	DBG_TRACE("Check CMAC mechanism");
	return check_mmac(slotid, subsystem, mgroup);
}

static CK_RV info_mcmac(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	return info_mmac_common(slotid, type, entry, info);
}

static CK_RV op_mcmac(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	return op_mmac_common(slotid, entry, args);
}

static void check_mhmac(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup)
{
	DBG_TRACE("Check HMAC mechanism");
	return check_mmac(slotid, subsystem, mgroup);
}

static CK_RV info_mhmac(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	return info_mmac_common(slotid, type, entry, info);
}

static CK_RV op_mhmac(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	return op_mmac_common(slotid, entry, args);
}

static CK_RV export_rsa_public_key(struct libobj_obj *obj,
				   struct smw_export_key_args *args)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_keypair_rsa *keypair_rsa = NULL;
	struct libobj_key_rsa_pair *key = get_subkey_from(obj);
	uint8_t *modulus = NULL;
	uint8_t *public_data = NULL;

	if (!obj || !args || !args->key_descriptor ||
	    !args->key_descriptor->buffer)
		return ret;

	keypair_rsa = &args->key_descriptor->buffer->rsa;

	modulus = calloc(1, keypair_rsa->modulus_length);
	if (!modulus)
		return CKR_HOST_MEMORY;

	public_data = calloc(1, keypair_rsa->public_length);
	if (!public_data) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	keypair_rsa->modulus = modulus;
	keypair_rsa->public_data = public_data;

	status = smw_export_key(args);
	ret = smw_status_to_ck_rv(status);

end:
	if (ret != CKR_OK) {
		if (modulus)
			free(modulus);

		if (public_data)
			free(public_data);
	} else {
		key->modulus.value = keypair_rsa->modulus;
		key->modulus.length = keypair_rsa->modulus_length;

		key->pub_exp.value = keypair_rsa->public_data;
		key->pub_exp.length = keypair_rsa->public_length;
	}

	return ret;
}

static CK_RV export_ecc_public_key(struct libobj_obj *obj,
				   struct smw_export_key_args *args)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_keypair_gen *keypair_gen = NULL;
	struct libobj_key_ec_pair *key = get_subkey_from(obj);
	uint8_t *point_q = NULL;
	size_t point_q_len = 0;
	size_t in_len = 0;

	if (!obj || !args || !args->key_descriptor ||
	    !args->key_descriptor->buffer)
		return CKR_ARGUMENTS_BAD;

	keypair_gen = &args->key_descriptor->buffer->gen;
	in_len = keypair_gen->public_length;

	/* Add DER ANSI X9.62 uncompress code byte */
	if (ADD_OVERFLOW(in_len, 1, &point_q_len))
		return CKR_ARGUMENTS_BAD;

	point_q = calloc(1, point_q_len);
	if (!point_q)
		return CKR_HOST_MEMORY;

	keypair_gen->public_data = &point_q[1];

	/* DER ANSI X9.62 uncompress code byte */
	point_q[0] = 0x04;

	status = smw_export_key(args);
	ret = smw_status_to_ck_rv(status);
	if (ret == CKR_OK) {
		key->point_q.number = point_q_len;
		key->point_q.array = point_q;
	} else {
		free(point_q);
	}

	return ret;
}

static bool is_ecc_key_type(smw_key_type_t type_name)
{
	if (type_name == SMW_KEY_TYPE_NAME_SECP_R1 ||
	    type_name == SMW_KEY_TYPE_NAME_BRAINPOOL_R1 ||
	    type_name == SMW_KEY_TYPE_NAME_BRAINPOOL_T1)
		return true;

	return false;
}

CK_RV libdev_get_mechanisms(CK_SLOT_ID slotid,
			    CK_MECHANISM_TYPE_PTR mechanismlist,
			    CK_ULONG_PTR count)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	struct mgroup *group = NULL;
	struct mentry *entry = NULL;
	unsigned int idx = 0;
	CK_MECHANISM_TYPE_PTR item = mechanismlist;
	CK_ULONG nb_mechanisms = 0;
	CK_FLAGS slot_flag = 0;

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

	/* Check if the Slot is present */
	if (!dev->slot.flags & CKF_TOKEN_PRESENT) {
		DBG_TRACE("Slot %lu is not present", slotid);
		return CKR_TOKEN_NOT_PRESENT;
	}

	DBG_TRACE("Get list of mechanisms for slot %lu", slotid);

	slot_flag = BIT(slotid);
	for (group = smw_mechanims; group->number; group++) {
		DBG_TRACE("Group %p has %u entries", group, group->number);
		for (idx = 0, entry = group->mechanism; idx < group->number;
		     idx++, entry++) {
			DBG_TRACE("Mechanism type 0x%lx", entry->type);
			if (entry->slot_flag & slot_flag) {
				DBG_TRACE("Mechanism 0x%lx supported",
					  entry->type);

				if (INC_OVERFLOW(nb_mechanisms, 1))
					return CKR_GENERAL_ERROR;

				if (item) {
					if (*count < nb_mechanisms)
						return CKR_BUFFER_TOO_SMALL;

					*item = entry->type;
					item++;
				}
			}
		}
	}

	*count = nb_mechanisms;

	return CKR_OK;
}

CK_RV libdev_get_mechanism_info(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	struct mgroup *group = NULL;
	struct mentry *entry = NULL;

	ret = find_mechanism(slotid, type, &group, &entry);
	if (ret == CKR_OK)
		ret = group->info(slotid, type, entry, info);

	return ret;
}

CK_RV libdev_validate_mechanism(CK_SLOT_ID slotid, CK_MECHANISM_PTR mech,
				CK_FLAGS op_flag)
{
	CK_RV ret = CKR_OK;
	CK_MECHANISM_INFO info = { 0 };

	ret = find_mechanism(slotid, mech->mechanism, NULL, NULL);
	if (ret != CKR_OK)
		return ret;

	ret = libdev_get_mechanism_info(slotid, mech->mechanism, &info);
	if (ret == CKR_OK && !(op_flag & info.flags))
		ret = CKR_MECHANISM_INVALID;

	return ret;
}

CK_RV libdev_operate_mechanism(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR mech, void *args)
{
	CK_RV ret = CKR_OK;
	CK_SLOT_ID slotid = 0;
	struct mgroup *group = NULL;
	struct mentry *entry = NULL;

	/* Before calling SMW, call the application callback */
	ret = libsess_callback(hsession, CKN_SURRENDER);
	if (ret != CKR_OK)
		return ret;

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		return ret;

	ret = find_mechanism(slotid, mech->mechanism, &group, &entry);
	if (ret == CKR_OK)
		ret = group->op(slotid, entry, args);

	return ret;
}

CK_RV libdev_import_key(CK_SESSION_HANDLE hsession, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	CK_SLOT_ID slotid = 0;
	const struct libdev *devinfo = NULL;
	struct smw_key_attributes key_attributes = { 0 };
	struct smw_import_key_args imp_args = { 0 };
	struct smw_key_descriptor key = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };

	DBG_TRACE("Import a Key");

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		return ret;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Set the key's buffer field to get the
	 * object key's buffer(s) to import.
	 */
	key.buffer = &keypair_buffer;

	ret = key_desc_to_smw(slotid, &key, &key_attributes, obj);
	if (ret != CKR_OK)
		return ret;

	imp_args.subsystem_name = devinfo->name;
	imp_args.key_descriptor = &key;
	imp_args.key_attributes = &key_attributes;

	status = smw_import_key(&imp_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Import Key on subsystem #%d SMW status %d return 0x%lx",
		  devinfo->name, status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

	return ret;
}

CK_RV libdev_get_key_attributes(CK_SESSION_HANDLE hsession,
				struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	CK_SLOT_ID slotid = 0;
	const struct libdev *devinfo = NULL;
	struct smw_key_descriptor key_descriptor = { 0 };
	struct smw_key_attributes *key_attr = NULL;
	struct smw_get_key_attributes_args attr_args = { 0 };
	struct smw_export_key_args args = { 0 };
	struct smw_keypair_buffer keypair_buffer = { 0 };

	DBG_TRACE("Get Key attributes");

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		goto end;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo) {
		ret = CKR_SLOT_ID_INVALID;
		goto end;
	}

	ret = libobj_get_id(obj, &key_descriptor.id);
	if (ret != CKR_OK)
		goto end;

	attr_args.subsystem_name = devinfo->name;
	attr_args.key_descriptor = &key_descriptor;

	status = smw_get_key_attributes(&attr_args);
	ret = smw_status_to_ck_rv(status);
	if (ret != CKR_OK)
		goto end;

	ret = key_desc_smw_to_pkcs11(obj, &attr_args);
	if (ret != CKR_OK)
		goto end;

	ret = get_key_allowed_algo(obj, &attr_args);
	if (ret != CKR_OK)
		goto end;

	key_attr = &attr_args.key_attributes;
	args_attr_get_key_usage(obj, key_attr->usage_flags);
	args_attr_get_key_storage(obj, key_attr->attributes);

	key_descriptor.buffer = &keypair_buffer;
	status = smw_get_key_buffers_lengths(&key_descriptor);
	if (status != SMW_STATUS_OK)
		goto end;

	args.key_descriptor = &key_descriptor;

	if (key_descriptor.type_name == SMW_KEY_TYPE_NAME_RSA)
		return export_rsa_public_key(obj, &args);
	else if (is_ecc_key_type(key_descriptor.type_name))
		return export_ecc_public_key(obj, &args);

end:
	DBG_TRACE("Get Key attributes from SMW status %d return %ld", status,
		  ret);

	return ret;
}

CK_RV libdev_delete_key(unsigned int key_id)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_delete_key_args key_args = { 0 };

	DBG_TRACE("Delete Key ID %X", key_id);
	if (!key_id)
		return ret;

	key_desc.id = key_id;
	key_args.key_descriptor = &key_desc;
	status = smw_delete_key(&key_args);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Delete Key status %d return %ld", status, ret);

	return ret;
}

CK_RV libdev_mechanisms_init(CK_SLOT_ID slotid)
{
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	struct mgroup *group = NULL;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	status = smw_osal_lib_init();
	if (status != SMW_STATUS_OK &&
	    status != SMW_STATUS_LIBRARY_ALREADY_INIT)
		return CKR_DEVICE_ERROR;

	for (group = smw_mechanims; group->number; group++)
		group->check(slotid, devinfo->name, group);

	return CKR_OK;
}

CK_RV libdev_rng(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pRandomData,
		 CK_ULONG ulRandomLen)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	CK_SLOT_ID slotid = 0;
	const struct libdev *devinfo = NULL;
	struct smw_rng_args args = { 0 };

	DBG_TRACE("Generate a random number");

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		return ret;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	args.subsystem_name = devinfo->name;
	args.output = pRandomData;

	if (SET_OVERFLOW(ulRandomLen, args.output_length))
		return CKR_ARGUMENTS_BAD;

	status = smw_rng(&args);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("RNG on subsystem #%d SMW status %d return 0x%lx",
		  devinfo->name, status, ret);
	return ret;
}

CK_RV libdev_cancel_operation(void **context)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_context_args args = { 0 };

	args.context = *context;

	status = smw_cancel_operation(&args);
	ret = smw_status_to_ck_rv(status);

	*context = args.context;

	DBG_TRACE("Cancel operation ret = %lx\n", ret);

	return ret;
}
