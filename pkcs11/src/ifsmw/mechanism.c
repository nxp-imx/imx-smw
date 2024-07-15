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

#include "dev_config.h"
#include "lib_context.h"
#include "lib_device.h"
#include "lib_session.h"
#include "lib_digest.h"
#include "libobj_types.h"
#include "pkcs11smw.h"
#include "types.h"
#include "lib_sign_verify.h"
#include "lib_cipher.h"

#include "args_attr.h"
#include "key_desc.h"

#include "trace.h"

#define NIST_STR	 "NIST"
#define BRAINPOOL_R1_STR "BRAINPOOL_R1"
#define BRAINPOOL_T1_STR "BRAINPOOL_T1"

#define AES_STR	 "AES"
#define DES_STR	 "DES"
#define DES3_STR "DES3"
#define HMAC_STR "HMAC"
#define SM4_STR	 "SM4"

#define ENCRYPT_STR "ENCRYPT"
#define DECRYPT_STR "DECRYPT"

#define ECDSA_STR "ECDSA"
#define RSA_STR	  "RSA"

#define PKCS1_1_5_STR "PKCS1_1_5"
#define PSS_STR	      "PSS"

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

smw_string_t smw_ec_name[] = { NIST_STR, BRAINPOOL_R1_STR, BRAINPOOL_T1_STR };

/**
 * struct mentry - Definition of a mechanism supported by each device
 * @type: Cryptoki Mechanism type
 * @slot_flag: Bit mask flag of a device supporting the mechanism
 * @smw_algo: SMW algorithm name for this mechanism
 * @smw_mode: SMW mode name for this mechanism, if any
 * @smw_hash: SMW hash name for this mechanism, if any
 * @smw_algo_id: SMW permitted algorithm for this mechanism
 * @nb_smw_curve: Number of SMW curves
 * @smw_curve: SMW curves names for this mechanism, if any
 */
struct mentry {
	CK_MECHANISM_TYPE type;
	CK_FLAGS slot_flag;
	smw_string_t smw_algo;
	smw_string_t smw_mode;
	smw_string_t smw_hash;
	smw_attr_algo_t smw_algo_id;
	unsigned int nb_smw_curve;
	smw_string_t *smw_curve;
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
#define M_ALGO(_algo_name, _mode_name, _hash_name, _algo_id, _id)              \
	{                                                                      \
		.type = CKM_##_id, .slot_flag = 0, .smw_algo = _algo_name,     \
		.smw_hash = _hash_name, .smw_mode = _mode_name,                \
		.smw_algo_id = _algo_id, .nb_smw_curve = 0, .smw_curve = NULL, \
	}

/* Macro filling a struct mentry for an algo or a list of algo */
#define M_ECKEYGEN(_curve, _nb_curve, _id)                                     \
	{                                                                      \
		.type = CKM_##_id, .slot_flag = 0, .smw_algo = ECDSA_STR,      \
		.smw_hash = NULL, .smw_mode = NULL, .smw_algo_id = 0,          \
		.nb_smw_curve = _nb_curve, .smw_curve = _curve,                \
	}

#define M_DIGEST(_hash, _id)                                                   \
	M_ALGO(STR(_hash), NULL, NULL, SMW_ATTR_HASH_##_hash, _id)

#define M_KEYGEN(_algo, _id)                                                   \
	{                                                                      \
		.type = CKM_##_id, .slot_flag = 0, .smw_algo = STR(_algo),     \
		.smw_hash = NULL, .smw_mode = NULL, .smw_algo_id = 0,          \
		.nb_smw_curve = 1, .smw_curve = NULL,                          \
	}

#define M_SIGN_ECDSA_ANY_HASH(_id)                                             \
	M_ALGO(ECDSA_STR, NULL, NULL,                                          \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(SMW_ATTR_CURVE_ANY,    \
							SMW_ATTR_HASH_ANY),    \
	       _id)

#define M_SIGN_ECDSA(_hash, _id)                                               \
	M_ALGO(ECDSA_STR, NULL, STR(_hash),                                    \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_ECDSA(                       \
		       SMW_ATTR_CURVE_ANY, SMW_ATTR_HASH_##_hash),             \
	       _id)

#define M_SIGN_RSA_ANY_HASH(_mode, _id)                                        \
	M_ALGO(RSA_STR, STR(_mode), NULL,                                      \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_##_mode,   \
						      SMW_ATTR_HASH_ANY, 0),   \
	       _id)

#define M_SIGN_RSA(_mode, _hash, _id)                                          \
	M_ALGO(RSA_STR, STR(_mode), STR(_hash),                                \
	       SMW_ATTR_ALGO_ASYMMETRIC_SIGNATURE_RSA(SMW_ATTR_MODE_##_mode,   \
						      SMW_ATTR_HASH_##_hash,   \
						      0),                      \
	       _id)

#define M_CIPHER(_algo, _mode, _mode_id, _id)                                  \
	M_ALGO(STR(_algo), STR(_mode), NULL,                                   \
	       SMW_ATTR_ALGO_SYMMETRIC_ENCRYPTION(SMW_ATTR_ALGO_##_algo,       \
						  SMW_ATTR_MODE_##_mode_id),   \
	       _id)

#define M_MAC(_algo, _mode, _mode_id, _id)                                     \
	M_ALGO(STR(_algo), STR(_mode), NULL,                                   \
	       SMW_ATTR_ALGO_MAC(SMW_ATTR_ALGO_##_algo,                        \
				 SMW_ATTR_MODE_##_mode_id, 0),                 \
	       _id)

#define M_HMAC(_mode, _hash, _id)                                              \
	M_ALGO(HMAC_STR, STR(_mode), STR(_hash),                               \
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
	M_GROUP(ARRAY_SIZE(msign_ecdsa), msign_ecdsa),
	M_GROUP(ARRAY_SIZE(msign_rsa), msign_rsa),
	M_GROUP(ARRAY_SIZE(mcipher), mcipher),
	M_GROUP(ARRAY_SIZE(mcmac), mcmac),
	M_GROUP(ARRAY_SIZE(mhmac), mhmac),
	{ 0 }
};

/**
 * smw_status_to_ck_rv() - Converts a SMW status to CK_RV value
 * @status: SMW status
 *
 * return:
 * CKR_DEVICE_MEMORY             - Device memory error
 * CKR_DEVICE_ERROR              - Device failure
 * CKR_BUFFER_TOO_SMALL          - Output buffer too small
 * CKR_OK                        - Success
 * CKR_BUFFER_TOO_SMALL          - Output buffer too small
 * CKR_SIGNATURE_INVALID         - Signature is invalid
 * CKR_SIGNATURE_LEN_RANGE       - Signature length is invalid
 */
static CK_RV smw_status_to_ck_rv(enum smw_status_code status)
{
	switch (status) {
	case SMW_STATUS_OK:
	case SMW_STATUS_KEY_POLICY_WARNING_IGNORED:
		return CKR_OK;

	case SMW_STATUS_ALLOC_FAILURE:
		return CKR_DEVICE_MEMORY;

	case SMW_STATUS_OUTPUT_TOO_SHORT:
		return CKR_BUFFER_TOO_SMALL;

	case SMW_STATUS_SIGNATURE_INVALID:
		return CKR_SIGNATURE_INVALID;

	case SMW_STATUS_SIGNATURE_LEN_INVALID:
		return CKR_SIGNATURE_LEN_RANGE;

	default:
		return CKR_DEVICE_ERROR;
	}
}

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
	smw_hash_algo_t hash_algo = NULL;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mdigest); i++) {
		if (mech_type == mdigest[i].type) {
			hash_algo = mdigest[i].smw_algo;
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

static CK_RV get_key_permitted_algo(smw_attr_algo_t *permitted_algo,
				    CK_SLOT_ID slotid, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	struct libmech_list *mech = NULL;
	struct mentry *entry = NULL;

	mech = get_key_mech(obj);

	/* Only one permitted algorithm is supported. */
	if (mech->number) {
		ret = find_mechanism(slotid, mech->mech[0], NULL, &entry);
		if (ret != CKR_OK) {
			DBG_TRACE("Key allowed mechanism 0x%lx error %ld",
				  mech->mech[0], ret);
		}

		DBG_TRACE("Key permitted algorithm 0x%" PRIx64,
			  entry->smw_algo_id);
		*permitted_algo = entry->smw_algo_id;
	}

	return ret;
}

static smw_cipher_mode_t get_cipher_mode(CK_MECHANISM_TYPE mech_type)
{
	smw_cipher_mode_t mode = NULL;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(mcipher); i++) {
		if (mech_type == mcipher[i].type) {
			mode = mcipher[i].smw_mode;
			break;
		}
	}

	return mode;
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
		status = smw_config_check_digest(subsystem, entry->smw_algo);
		DBG_TRACE("Subsystem #%d digest %s: %d", subsystem,
			  (char *)entry->smw_algo, status);
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
	hash_args.algo_name = entry->smw_algo;

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
	smw_string_t *curve = NULL;
	unsigned int idx = 0;
	unsigned int idx_algo = 0;
	struct smw_key_info info = { 0 };

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		if (entry->nb_smw_curve > 1)
			curve = &entry->smw_curve[0];
		else
			curve = &entry->smw_algo;

		for (idx_algo = 0; idx_algo < entry->nb_smw_curve;
		     idx_algo++, curve++) {
			info.key_type_name = *curve;

			status =
				smw_config_check_generate_key(subsystem, &info);
			DBG_TRACE("Subsystem #%d Key Generate %s: %d",
				  subsystem, info.key_type_name, status);

			if (status == SMW_STATUS_OK)
				SET_BITS(entry->slot_flag, slot_flag);
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
	smw_string_t *curve = NULL;
	unsigned int idx = 0;
	struct smw_key_info keyinfo = { 0 };

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	if (entry->nb_smw_curve > 1)
		curve = &entry->smw_curve[0];
	else
		curve = &entry->smw_algo;

	for (; idx < entry->nb_smw_curve; idx++, curve++) {
		keyinfo.key_type_name = *curve;
		keyinfo.security_size = 0;

		status = smw_config_check_generate_key(devinfo->name, &keyinfo);
		DBG_TRACE("Subsystem #%d Key Generate %s: %d", devinfo->name,
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

	ret = key_desc_setup(&key, obj);
	if (ret != CKR_OK)
		return ret;

	ret = get_key_permitted_algo(&key_attributes.permitted_algo, slotid,
				     obj);
	if (ret != CKR_OK)
		return ret;

	gen_args.subsystem_name = devinfo->name;
	gen_args.key_descriptor = &key;

	args_attrs_key_usage(&key_attributes.usage_flags, obj);
	args_attr_key_storage(&key_attributes.attributes, obj);
	gen_args.key_attributes = &key_attributes;

	status = smw_generate_key(&gen_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Generate Key on subsystem #%d status %d return %ld",
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
		info.algo = entry->smw_algo;
		info.type = entry->smw_mode;
		info.hash = entry->smw_hash;

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

	sign_verify_info.algo = entry->smw_algo;
	sign_verify_info.type = entry->smw_mode;
	sign_verify_info.hash = entry->smw_hash;

	/* @info flag is set with Sign flag or Verify flag or both */
	status = smw_config_check_sign(devinfo->name, &sign_verify_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_SIGN;

	status = smw_config_check_verify(devinfo->name, &sign_verify_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_VERIFY;

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

static CK_RV op_msign_common(CK_SLOT_ID slotid, struct mentry *entry,
			     struct lib_signature_params *params,
			     unsigned int key_id)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	struct lib_signature_ctx *ctx = params->ctx;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_sign_verify_args smw_args = { 0 };

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	smw_args.subsystem_name = devinfo->name;
	key_desc.id = key_id;
	smw_args.key_descriptor = &key_desc;
	smw_args.sign_algo = entry->smw_algo_id;

	if (!entry->smw_hash)
		smw_args.sign_algo =
			SMW_ATTR_SET_HASH(smw_args.sign_algo,
					  get_hash_algo_id(ctx->hash_mech));

	if (ctx->salt_len)
		if (SET_OVERFLOW(SMW_ATTR_SET_SALT_LENGTH(smw_args.sign_algo,
							  ctx->salt_len),
				 smw_args.sign_algo))
			return CKR_ARGUMENTS_BAD;

	smw_args.message = params->pdata;
	if (SET_OVERFLOW(params->uldatalen, smw_args.message_length))
		return CKR_ARGUMENTS_BAD;

	smw_args.signature = params->psignature;
	if (SET_OVERFLOW(params->ulsignaturelen, smw_args.signature_length))
		return CKR_ARGUMENTS_BAD;

	if (params->op_flag == CKF_SIGN) {
		status = smw_sign(&smw_args);

		/* Update signature length */
		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			params->ulsignaturelen = smw_args.signature_length;
	} else {
		status = smw_verify(&smw_args);
	}

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("%s on subsystem #%d status %d return %ld",
		  params->op_flag == CKF_SIGN ? "Sign" : "Verify",
		  smw_args.subsystem_name, status, ret);

	return ret;
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
		info.key_type_name = entry->smw_algo;
		info.mode = entry->smw_mode;
		info.op_type = ENCRYPT_STR;
		status = smw_config_check_cipher(subsystem, &info);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);

		info.op_type = DECRYPT_STR;
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

	cipher_info.key_type_name = entry->smw_algo;
	cipher_info.mode = entry->smw_mode;

	cipher_info.op_type = ENCRYPT_STR;
	status = smw_config_check_cipher(devinfo->name, &cipher_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_ENCRYPT;

	cipher_info.op_type = DECRYPT_STR;
	status = smw_config_check_cipher(devinfo->name, &cipher_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_DECRYPT;

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
		  params->op_flag == CKF_ENCRYPT ? ENCRYPT_STR : DECRYPT_STR,
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
			key_desc_ptr[i].type_name = AES_STR;
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

	DBG_TRACE("Cipher mode = %s", smw_init_args->mode_name);

	if (op_flag == CKF_ENCRYPT)
		smw_init_args->operation_name = ENCRYPT_STR;
	else
		smw_init_args->operation_name = DECRYPT_STR;

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
	    (ctx->current_state == OP_INIT && params->state == OP_UPDATE)) {
		if (set_smw_init_args(ctx, smw_init_args_ptr, &key_buffer,
				      &keys_desc_ptr, &key_descriptor[0],
				      devinfo->name, params->op_flag) != CKR_OK)
			goto end;
	}

	if (SET_OVERFLOW(params->input_length, smw_data_args.input_length)) {
		if (params->op_flag == CKF_ENCRYPT)
			ret = CKR_DATA_LEN_RANGE;
		else
			ret = CKR_ENCRYPTED_DATA_LEN_RANGE;

		goto end;
	}

	if (SET_OVERFLOW(params->output_length, smw_data_args.output_length)) {
		if (params->op_flag == CKF_ENCRYPT)
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

	mac_info.key_type_name = entry->smw_algo;
	mac_info.mac_algo = entry->smw_mode;
	mac_info.hash_algo = entry->smw_hash;

	status = smw_config_check_mac(devinfo->name, &mac_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_SIGN | CKF_VERIFY;

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

	key_desc.id = get_key_id_from((struct libobj_obj *)ctx->hkey, cipher);

	smw_args.subsystem_name = devinfo->name;
	smw_args.key_descriptor = &key_desc;

	smw_args.input = params->pdata;
	if (SET_OVERFLOW(params->uldatalen, smw_args.input_length))
		return ret;

	smw_args.mac = params->psignature;
	if (SET_OVERFLOW(params->ulsignaturelen, smw_args.mac_length))
		return ret;

	smw_args.algo_name = entry->smw_mode;

	/* Get hash algorithm */
	if (entry->smw_hash)
		smw_args.hash_name = entry->smw_hash;
	else if (ctx->hash_mech)
		smw_args.hash_name = get_hash_algo(ctx->hash_mech);

	if (params->op_flag == CKF_SIGN) {
		status = smw_mac(&smw_args);

		/* Update MAC length */
		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			params->ulsignaturelen = smw_args.mac_length;
	} else {
		status = smw_mac_verify(&smw_args);
	}

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("%s on subsystem #%d status %d return %ld",
		  params->op_flag == CKF_SIGN ? "Sign" : "Verify",
		  smw_args.subsystem_name, status, ret);

	return ret;
}

static void check_mcmac(CK_SLOT_ID slotid, smw_subsystem_t subsystem,
			struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx;
	CK_FLAGS slot_flag = 0;
	struct mentry *entry = NULL;
	struct smw_mac_info info = { 0 };

	slot_flag = BIT(slotid);

	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		info.key_type_name = entry->smw_algo;
		info.mac_algo = entry->smw_mode;
		status = smw_config_check_mac(subsystem, &info);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
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
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	struct smw_mac_info info = { 0 };
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;

	DBG_TRACE("Check HMAC mechanism");

	/*
	 * smw_config_check_mac() checks the key type, the MAC algorithm
	 * (optional) and the hash algorithm (optional).
	 *
	 * Slot flag is set if:
	 *  - sign or verify or both operations are supported
	 */

	info.key_type_name = HMAC_STR;

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		info.mac_algo = entry->smw_algo;
		info.hash_algo = entry->smw_hash;

		status = smw_config_check_mac(subsystem, &info);
		DBG_TRACE("Subsystem #%d MAC mechanism %lu: %d", subsystem,
			  entry->type, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
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

	ret = key_desc_setup(&key, obj);
	if (ret != CKR_OK)
		return ret;

	ret = get_key_permitted_algo(&key_attributes.permitted_algo, slotid,
				     obj);
	if (ret != CKR_OK)
		return ret;

	imp_args.subsystem_name = devinfo->name;
	imp_args.key_descriptor = &key;

	args_attrs_key_usage(&key_attributes.usage_flags, obj);
	args_attr_key_storage(&key_attributes.attributes, obj);
	imp_args.key_attributes = &key_attributes;

	status = smw_import_key(&imp_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Import Key on subsystem #%d status %d return %ld",
		  devinfo->name, status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

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

	DBG_TRACE("RNG on subsystem #%d status %d return %ld", devinfo->name,
		  status, ret);
	return ret;
}

CK_RV libdev_cancel_operation(void **context)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_context_args args = { 0 };

	args.context = (struct smw_op_context *)*context;

	status = smw_cancel_operation(&args);
	ret = smw_status_to_ck_rv(status);

	*context = args.context;

	DBG_TRACE("Cancel operation ret = %lx\n", ret);

	return ret;
}
