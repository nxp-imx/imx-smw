// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2023 NXP
 */

#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "smw_config.h"
#include "smw_crypto.h"
#include "smw_osal.h"

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
#include "tlv_encode.h"

#include "trace.h"

#define SMW_RSA_PKCS1_V1_5_SIGN_TYPE "RSASSA-PKCS1-V1_5"
#define SMW_RSA_PSS_SIGN_TYPE	     "RSASSA-PSS"

#define ENCRYPT_STR "ENCRYPT"
#define DECRYPT_STR "DECRYPT"

#define AES_STR	 "AES"
#define DES_STR	 "DES"
#define DES3_STR "DES3"

struct mgroup;
struct mentry;

static void check_mdigest(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mdigest(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mdigest(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_meckeygen(CK_SLOT_ID slotid, const char *subsystem,
			    struct mgroup *mgroup);
static CK_RV info_meckeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_meckeygen(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_mkeygen(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mkeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mkeygen(CK_SLOT_ID slotid, struct mentry *entry, void *args);
static void check_msign_ecdsa(CK_SLOT_ID slotid, const char *subsystem,
			      struct mgroup *mgroup);
static CK_RV info_msign_ecdsa(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_msign_ecdsa(CK_SLOT_ID slotid, struct mentry *entry,
			    void *args);
static void check_msign_rsa_pkcs_v1_5(CK_SLOT_ID slotid, const char *subsystem,
				      struct mgroup *mgroup);
static CK_RV info_msign_rsa_pkcs_v1_5(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				      struct mentry *entry,
				      CK_MECHANISM_INFO_PTR info);
static CK_RV op_msign_rsa_pkcs_v1_5(CK_SLOT_ID slotid, struct mentry *entry,
				    void *args);
static void check_msign_rsa_pss(CK_SLOT_ID slotid, const char *subsystem,
				struct mgroup *mgroup);
static CK_RV info_msign_rsa_pss(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				struct mentry *entry,
				CK_MECHANISM_INFO_PTR info);
static CK_RV op_msign_rsa_pss(CK_SLOT_ID slotid, struct mentry *entry,
			      void *args);
static void check_mcipher_aes(CK_SLOT_ID slotid, const char *subsystem,
			      struct mgroup *mgroup);
static CK_RV info_mcipher_aes(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mcipher_aes(CK_SLOT_ID slotid, struct mentry *entry,
			    void *args);
static void check_mcipher_des(CK_SLOT_ID slotid, const char *subsystem,
			      struct mgroup *mgroup);
static CK_RV info_mcipher_des(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mcipher_des(CK_SLOT_ID slotid, struct mentry *entry,
			    void *args);
static void check_mcipher_des3(CK_SLOT_ID slotid, const char *subsystem,
			       struct mgroup *mgroup);
static CK_RV info_mcipher_des3(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			       struct mentry *entry,
			       CK_MECHANISM_INFO_PTR info);
static CK_RV op_mcipher_des3(CK_SLOT_ID slotid, struct mentry *entry,
			     void *args);

const char *smw_ec_name[] = { "NIST", "BRAINPOOL_R1", "BRAINPOOL_T1" };

/**
 * struct mentry - Definition of a mechanism supported by each device
 * @type: Cryptoki Mechanism type
 * @slot_flag: Bit mask flag of a device supporting the mechanism
 * @nb_smw_algo: Number of SMW algorithm for this mechanism
 * @smw_algo: Mechanism's algorithm(s) definition corresponding to SMW
 * @smw_hash: Digest algorithm name used for the mechanism (SMW name)
 */
struct mentry {
	CK_MECHANISM_TYPE type;
	CK_FLAGS slot_flag;
	unsigned int nb_smw_algo;
	void *smw_algo;
	void *smw_hash;
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

	void (*check)(CK_SLOT_ID slotid, const char *subsystem,
		      struct mgroup *mgroup);
	CK_RV(*info)
	(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type, struct mentry *entry,
	 CK_MECHANISM_INFO_PTR info);
	CK_RV (*op)(CK_SLOT_ID slotid, struct mentry *entry, void *args);
};

/* Macro filling a struct mentry for a single algo without hash */
#define M_ALGO_NO_HASH(name, id)    M_ALGO(STR(name), NULL_PTR, id)
#define M_ALGO_HASH(name, hash, id) M_ALGO(STR(name), STR(hash), id)

/* Macro filling a struct mentry for a single algo using a hash */
#define M_ALGO(_name, _hash, id)                                               \
	{                                                                      \
		.type = CKM_##id, .slot_flag = 0, .nb_smw_algo = 1,            \
		.smw_algo = _name, .smw_hash = _hash                           \
	}

/* Macro filling a struct mentry for an algo or a list of algo */
#define M_ALGO_MULTI(ptr, nb, id)                                              \
	{                                                                      \
		.type = CKM_##id, .slot_flag = 0, .nb_smw_algo = nb,           \
		.smw_algo = ptr,                                               \
	}

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
	M_ALGO_NO_HASH(SHA1, SHA_1),	M_ALGO_NO_HASH(SHA224, SHA224),
	M_ALGO_NO_HASH(SHA256, SHA256), M_ALGO_NO_HASH(SHA384, SHA384),
	M_ALGO_NO_HASH(SHA512, SHA512),
};

/*
 * EC Key Generate mechanisms
 */
static struct mentry meckeygen[] = {
	M_ALGO_MULTI(smw_ec_name, ARRAY_SIZE(smw_ec_name), EC_KEY_PAIR_GEN),
};

/*
 * Key Generate mechanism
 * Cipher and RSA keys
 */
static struct mentry mkeygen[] = {
	M_ALGO_NO_HASH(AES, AES_KEY_GEN),
	M_ALGO_NO_HASH(DES, DES_KEY_GEN),
	M_ALGO_NO_HASH(DES3, DES3_KEY_GEN),
	M_ALGO_NO_HASH(RSA, RSA_PKCS_KEY_PAIR_GEN),
};

/*
 * Signature mechanism
 */
static struct mentry msign_ecdsa[] = {
	M_ALGO_NO_HASH(ECDSA, ECDSA),
	M_ALGO_HASH(ECDSA, SHA1, ECDSA_SHA1),
	M_ALGO_HASH(ECDSA, SHA224, ECDSA_SHA224),
	M_ALGO_HASH(ECDSA, SHA256, ECDSA_SHA256),
	M_ALGO_HASH(ECDSA, SHA384, ECDSA_SHA384),
	M_ALGO_HASH(ECDSA, SHA512, ECDSA_SHA512),
};

static struct mentry msign_rsa_pkcs_v1_5[] = {
	M_ALGO_NO_HASH(RSA_PKCS1V15, RSA_PKCS),
	M_ALGO_HASH(RSA_PKCS1V15, SHA1, SHA1_RSA_PKCS),
	M_ALGO_HASH(RSA_PKCS1V15, SHA224, SHA224_RSA_PKCS),
	M_ALGO_HASH(RSA_PKCS1V15, SHA256, SHA256_RSA_PKCS),
	M_ALGO_HASH(RSA_PKCS1V15, SHA384, SHA384_RSA_PKCS),
	M_ALGO_HASH(RSA_PKCS1V15, SHA512, SHA512_RSA_PKCS),
};

static struct mentry msign_rsa_pss[] = {
	M_ALGO_NO_HASH(RSA_PSS, RSA_PKCS_PSS),
	M_ALGO_HASH(RSA_PSS, SHA1, SHA1_RSA_PKCS_PSS),
	M_ALGO_HASH(RSA_PSS, SHA224, SHA224_RSA_PKCS_PSS),
	M_ALGO_HASH(RSA_PSS, SHA256, SHA256_RSA_PKCS_PSS),
	M_ALGO_HASH(RSA_PSS, SHA384, SHA384_RSA_PKCS_PSS),
	M_ALGO_HASH(RSA_PSS, SHA512, SHA512_RSA_PKCS_PSS),
};

/*
 * Cipher mechanisms
 */
static struct mentry mcipher_aes[] = { M_ALGO_NO_HASH(AES, AES_CBC),
				       M_ALGO_NO_HASH(AES, AES_CTR),
				       M_ALGO_NO_HASH(AES, AES_CTS),
				       M_ALGO_NO_HASH(AES, AES_ECB),
				       M_ALGO_NO_HASH(AES, AES_XTS) };

static struct mentry mcipher_des[] = { M_ALGO_NO_HASH(DES, DES_CBC),
				       M_ALGO_NO_HASH(DES, DES_ECB) };

static struct mentry mcipher_des3[] = {
	M_ALGO_NO_HASH(DES3, DES3_CBC),
	M_ALGO_NO_HASH(DES3, DES3_ECB),
};

/*
 * All SMW mechanisms
 */
static struct mgroup smw_mechanims[] = {
	M_GROUP(ARRAY_SIZE(mdigest), mdigest),
	M_GROUP(ARRAY_SIZE(meckeygen), meckeygen),
	M_GROUP(ARRAY_SIZE(mkeygen), mkeygen),
	M_GROUP(ARRAY_SIZE(msign_ecdsa), msign_ecdsa),
	M_GROUP(ARRAY_SIZE(msign_rsa_pkcs_v1_5), msign_rsa_pkcs_v1_5),
	M_GROUP(ARRAY_SIZE(msign_rsa_pss), msign_rsa_pss),
	M_GROUP(ARRAY_SIZE(mcipher_aes), mcipher_aes),
	M_GROUP(ARRAY_SIZE(mcipher_des), mcipher_des),
	M_GROUP(ARRAY_SIZE(mcipher_des3), mcipher_des3),
	{ 0 },
};

#define GET_ALGO_NAME(entry, idx)                                              \
	({                                                                     \
		__typeof__(entry) _entry = entry;                              \
		(_entry->nb_smw_algo > 1) ?                                    \
			((const char **)_entry->smw_algo)[idx] :               \
			_entry->smw_algo;                                      \
	})

#define CIPHER_ALGO(_key_type_, _cipher_mode_)                                 \
	{                                                                      \
		.mech_type = CKM_##_key_type_##_##_cipher_mode_,               \
		.cipher_mode = #_cipher_mode_                                  \
	}

/**
 * struct cipher_algo_info - Information about cipher algorithm
 * @mech_type: Cipher mechanism
 * @cipher_mode: Cipher mode
 */
struct cipher_algo_info {
	CK_MECHANISM_TYPE mech_type;
	smw_cipher_mode_t cipher_mode;
};

static struct cipher_algo_info cipher_algos[] = {
	CIPHER_ALGO(AES, ECB), CIPHER_ALGO(AES, CBC),  CIPHER_ALGO(AES, CTR),
	CIPHER_ALGO(AES, CTS), CIPHER_ALGO(AES, XTS),  CIPHER_ALGO(DES, ECB),
	CIPHER_ALGO(DES, CBC), CIPHER_ALGO(DES3, ECB), CIPHER_ALGO(DES3, CBC)
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

static void check_mdigest(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		status = smw_config_check_digest(subsystem, entry->smw_algo);
		DBG_TRACE("%s digest %s: %d", subsystem,
			  (char *)entry->smw_algo, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static void check_keygen_common(CK_SLOT_ID slotid, const char *subsystem,
				struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	unsigned int idx_algo = 0;
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;
	struct smw_key_info info = { 0 };

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		for (idx_algo = 0; idx_algo < entry->nb_smw_algo; idx_algo++) {
			info.key_type_name = GET_ALGO_NAME(entry, idx_algo);

			status =
				smw_config_check_generate_key(subsystem, &info);
			DBG_TRACE("%s Key Generate %s: %d", subsystem,
				  info.key_type_name, status);

			if (status == SMW_STATUS_OK)
				SET_BITS(entry->slot_flag, slot_flag);
		}
	}
}

static void check_meckeygen(CK_SLOT_ID slotid, const char *subsystem,
			    struct mgroup *mgroup)
{
	DBG_TRACE("Check EC Key generate");
	check_keygen_common(slotid, subsystem, mgroup);
}

static void check_mkeygen(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup)
{
	DBG_TRACE("Check Key generate");
	check_keygen_common(slotid, subsystem, mgroup);
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
	hash_args.algo_name = GET_ALGO_NAME(entry, 0);

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

	DBG_TRACE("Digest on %s status %d return %ld", devinfo->name, status,
		  ret);
	return ret;
}

static CK_RV info_keygen_common(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				struct mentry *entry,
				CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	const struct libdev *devinfo = NULL;
	unsigned int idx = 0;
	struct smw_key_info keyinfo = { 0 };

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	for (; idx < entry->nb_smw_algo; idx++) {
		keyinfo.key_type_name = GET_ALGO_NAME(entry, idx);
		keyinfo.security_size = 0;

		status = smw_config_check_generate_key(devinfo->name, &keyinfo);
		DBG_TRACE("%s Key Generate %s: %d", devinfo->name,
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

static CK_RV build_key_allowed_algos(struct smw_tlv *tlv_algos,
				     CK_SLOT_ID slotid, struct libobj_obj *obj)
{
	CK_RV ret = CKR_OK;
	size_t idx = 0;
	struct libmech_list *mech = NULL;
	struct mentry *entry = NULL;
	struct smw_tlv tlv_algo_params = { 0 };

	mech = get_key_mech(obj);

	for (; idx < mech->number && ret == CKR_OK; idx++) {
		ret = find_mechanism(slotid, mech->mech[idx], NULL, &entry);
		if (ret != CKR_OK) {
			DBG_TRACE("Key allowed mechanism 0x%lx error %ld",
				  mech->mech[idx], ret);
			break;
		}

		DBG_TRACE("Key allowed mechanism %s", (char *)entry->smw_algo);
		if (entry->smw_hash) {
			DBG_TRACE("\t with HASH=%s", (char *)entry->smw_hash);
			ret = tlv_encode_string(&tlv_algo_params, SMW_ATTR_HASH,
						entry->smw_hash);
		}

		if (ret == CKR_OK)
			ret = tlv_encode_concat_string(tlv_algos, SMW_ATTR_ALGO,
						       entry->smw_algo,
						       &tlv_algo_params);

		tlv_encode_free(&tlv_algo_params);
	}

	return ret;
}

static CK_RV op_keygen_common(CK_SLOT_ID slotid, struct libobj_obj *obj)
{
	CK_RV ret = CKR_SLOT_ID_INVALID;
	const struct libdev *devinfo = NULL;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_tlv key_attr = { 0 };
	struct smw_tlv allowed_algos = { 0 };
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key = { 0 };

	DBG_TRACE("Common Generate Key mechanism");
	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return ret;

	ret = key_desc_setup(&key, obj);
	if (ret != CKR_OK)
		return ret;

	ret = build_key_allowed_algos(&allowed_algos, slotid, obj);
	if (ret != CKR_OK)
		goto end;

	ret = args_attrs_key_policy(&key_attr, obj, &allowed_algos);
	if (ret != CKR_OK)
		goto end;

	gen_args.subsystem_name = devinfo->name;
	gen_args.key_descriptor = &key;

	ret = args_attr_generate_key(&key_attr, obj);
	if (ret != CKR_OK)
		goto end;

	gen_args.key_attributes_list = (unsigned char *)key_attr.string;
	gen_args.key_attributes_list_length = key_attr.length;

	status = smw_generate_key(&gen_args);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Generate Key on %s status %d return %ld", devinfo->name,
		  status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

end:
	tlv_encode_free(&allowed_algos);
	tlv_encode_free(&key_attr);

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

static void check_msign_ecdsa(CK_SLOT_ID slotid, const char *subsystem,
			      struct mgroup *mgroup)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	unsigned int ecdsa_idx = 0;
	struct smw_signature_info info = { 0 };
	struct mentry *entry = NULL;
	CK_FLAGS slot_flag = 0;

	DBG_TRACE("Check ECDSA Signature mechanism");

	/*
	 * smw_config_check_sign() checks the key type, the hash algorithm
	 * (optional) and the signature type (optional).
	 *
	 * Slot flag is set if:
	 *  - sign or verify or both operations are supported
	 *  - at least one ECDSA key type is supported
	 */

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		if (entry->smw_hash)
			info.hash_algo = entry->smw_hash;

		for (ecdsa_idx = 0; ecdsa_idx < ARRAY_SIZE(smw_ec_name);
		     ecdsa_idx++) {
			info.key_type_name = smw_ec_name[ecdsa_idx];

			status = smw_config_check_sign(subsystem, &info);
			DBG_TRACE("%s sign mechanism %lu: %d", subsystem,
				  entry->type, status);
			if (status == SMW_STATUS_OK)
				SET_BITS(entry->slot_flag, slot_flag);

			status = smw_config_check_verify(subsystem, &info);
			DBG_TRACE("%s verify mechanism %lu: %d", subsystem,
				  entry->type, status);
			if (status == SMW_STATUS_OK)
				SET_BITS(entry->slot_flag, slot_flag);
		}
	}
}

static void check_msign_rsa_common(CK_SLOT_ID slotid, const char *subsystem,
				   struct mgroup *mgroup,
				   struct smw_signature_info *info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx = 0;
	CK_FLAGS slot_flag = 0;
	struct mentry *entry = NULL;

	/*
	 * smw_config_check_sign() checks the key type, the hash algorithm
	 * (optional) and the signature type (optional).
	 *
	 * Slot flag is set if:
	 *  - sign or verify or both operations are supported
	 */

	info->key_type_name = "RSA";

	slot_flag = BIT(slotid);
	for (entry = mgroup->mechanism; idx < mgroup->number; idx++, entry++) {
		if (entry->smw_hash)
			info->hash_algo = entry->smw_hash;

		status = smw_config_check_sign(subsystem, info);
		DBG_TRACE("%s sign mechanism %lu: %d", subsystem, entry->type,
			  status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);

		status = smw_config_check_verify(subsystem, info);
		DBG_TRACE("%s verify mechanism %lu: %d", subsystem, entry->type,
			  status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
}

static void check_msign_rsa_pkcs_v1_5(CK_SLOT_ID slotid, const char *subsystem,
				      struct mgroup *mgroup)
{
	struct smw_signature_info info = {
		.signature_type = SMW_RSA_PKCS1_V1_5_SIGN_TYPE
	};

	DBG_TRACE("Check RSA PKCS V1_5 Signature mechanism");

	check_msign_rsa_common(slotid, subsystem, mgroup, &info);
}

static void check_msign_rsa_pss(CK_SLOT_ID slotid, const char *subsystem,
				struct mgroup *mgroup)
{
	struct smw_signature_info info = { .signature_type =
						   SMW_RSA_PSS_SIGN_TYPE };

	DBG_TRACE("Check RSA PSS Signature mechanism");

	check_msign_rsa_common(slotid, subsystem, mgroup, &info);
}

static CK_RV info_msign_ecdsa(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	unsigned int ecdsa_idx = 0;
	struct smw_signature_info sign_verify_info = { 0 };
	const struct libdev *devinfo = NULL;

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

	if (entry->smw_hash)
		sign_verify_info.hash_algo = entry->smw_hash;

	/*
	 * @info flag is set with Sign flag or Verify flag or both
	 *
	 * If at least one ECDSA key type is supported by the operation,
	 * @info flag is set
	 */
	for (ecdsa_idx = 0; ecdsa_idx < ARRAY_SIZE(smw_ec_name); ecdsa_idx++) {
		sign_verify_info.key_type_name = smw_ec_name[ecdsa_idx];

		status =
			smw_config_check_sign(devinfo->name, &sign_verify_info);
		if (status == SMW_STATUS_OK)
			info->flags |= CKF_SIGN;

		status = smw_config_check_verify(devinfo->name,
						 &sign_verify_info);
		if (status == SMW_STATUS_OK)
			info->flags |= CKF_VERIFY;
	}

	/*
	 * Call specific device mechanism information function
	 * to complete the global setting.
	 */
	if (dev_mech_info[slotid])
		ret = dev_mech_info[slotid](type, info);

	return ret;
}

static CK_RV info_msign_rsa_common(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				   struct mentry *entry,
				   CK_MECHANISM_INFO_PTR info,
				   struct smw_signature_info *sign_verify_info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Signature global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	sign_verify_info->key_type_name = "RSA";

	if (entry->smw_hash)
		sign_verify_info->hash_algo = entry->smw_hash;
	else
		sign_verify_info->hash_algo = NULL_PTR;

	/* @info flag is set with Sign flag or Verify flag or both */
	status = smw_config_check_sign(devinfo->name, sign_verify_info);
	if (status == SMW_STATUS_OK)
		info->flags |= CKF_SIGN;

	status = smw_config_check_verify(devinfo->name, sign_verify_info);
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

static CK_RV info_msign_rsa_pkcs_v1_5(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				      struct mentry *entry,
				      CK_MECHANISM_INFO_PTR info)
{
	struct smw_signature_info sign_verify_info = {
		.signature_type = SMW_RSA_PKCS1_V1_5_SIGN_TYPE
	};

	DBG_TRACE("Return info of 0x%lx signature mechanism", type);

	return info_msign_rsa_common(slotid, type, entry, info,
				     &sign_verify_info);
}

static CK_RV info_msign_rsa_pss(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				struct mentry *entry,
				CK_MECHANISM_INFO_PTR info)
{
	struct smw_signature_info sign_verify_info = {
		.signature_type = SMW_RSA_PSS_SIGN_TYPE
	};

	DBG_TRACE("Return info of 0x%lx signature mechanism", type);

	return info_msign_rsa_common(slotid, type, entry, info,
				     &sign_verify_info);
}

static CK_RV op_msign_common(struct smw_sign_verify_args *smw_args,
			     struct mentry *entry,
			     struct lib_signature_params *params,
			     const char *signature_type)
{
	CK_RV ret = CKR_ARGUMENTS_BAD;
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int i = 0;
	struct smw_tlv attr = { 0 };
	struct lib_signature_ctx *ctx = (struct lib_signature_ctx *)params->ctx;

	smw_args->message = params->pdata;
	if (SET_OVERFLOW(params->uldatalen, smw_args->message_length))
		return ret;

	smw_args->signature = params->psignature;
	if (SET_OVERFLOW(params->ulsignaturelen, smw_args->signature_length))
		return ret;

	/* Get hash algorithm */
	if (entry->smw_hash) {
		smw_args->algo_name = entry->smw_hash;
	} else if (ctx->hash_mech) {
		for (; i < ARRAY_SIZE(mdigest); i++) {
			if (ctx->hash_mech == mdigest[i].type) {
				smw_args->algo_name =
					(char *)mdigest[i].smw_algo;
				break;
			}
		}
	}

	/* Build attribute list */
	ret = args_attr_sign_verify(&attr, signature_type, ctx->salt_len);
	if (ret != CKR_OK)
		goto end;

	if (attr.string) {
		smw_args->attributes_list = (unsigned char *)attr.string;
		smw_args->attributes_list_length = attr.length;
	}

	if (params->op_flag == CKF_SIGN) {
		status = smw_sign(smw_args);

		/* Update signature length */
		if (status == SMW_STATUS_OK ||
		    status == SMW_STATUS_OUTPUT_TOO_SHORT)
			params->ulsignaturelen = smw_args->signature_length;
	} else {
		status = smw_verify(smw_args);
	}

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("%s on %s status %d return %ld",
		  params->op_flag == CKF_SIGN ? "Sign" : "Verify",
		  smw_args->subsystem_name, status, ret);

end:
	tlv_encode_free(&attr);

	return ret;
}

static CK_RV op_msign_ecdsa(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	const struct libdev *devinfo = NULL;
	struct lib_signature_ctx *ctx = NULL;
	struct lib_signature_params *params = NULL;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_sign_verify_args smw_args = { 0 };

	DBG_TRACE("ECDSA Signature mechanism");

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = (struct lib_signature_params *)args;
	ctx = (struct lib_signature_ctx *)params->ctx;

	key_desc.id = get_key_id_from((struct libobj_obj *)ctx->hkey, ec_pair);

	smw_args.subsystem_name = devinfo->name;
	smw_args.key_descriptor = &key_desc;

	return op_msign_common(&smw_args, entry, params, NULL);
}

static CK_RV op_msign_rsa_pkcs_v1_5(CK_SLOT_ID slotid, struct mentry *entry,
				    void *args)
{
	const struct libdev *devinfo = NULL;
	struct lib_signature_ctx *ctx = NULL;
	struct lib_signature_params *params = NULL;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_sign_verify_args smw_args = { 0 };

	DBG_TRACE("RSA PKCS V1_5 Signature mechanism");

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = (struct lib_signature_params *)args;
	ctx = (struct lib_signature_ctx *)params->ctx;

	key_desc.id = get_key_id_from((struct libobj_obj *)ctx->hkey, rsa_pair);

	smw_args.subsystem_name = devinfo->name;
	smw_args.key_descriptor = &key_desc;

	return op_msign_common(&smw_args, entry, params,
			       SMW_RSA_PKCS1_V1_5_SIGN_TYPE);
}

static CK_RV op_msign_rsa_pss(CK_SLOT_ID slotid, struct mentry *entry,
			      void *args)
{
	const struct libdev *devinfo = NULL;
	struct lib_signature_ctx *ctx = NULL;
	struct lib_signature_params *params = NULL;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_sign_verify_args smw_args = { 0 };

	DBG_TRACE("RSA PSS Signature mechanism");

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = (struct lib_signature_params *)args;
	ctx = (struct lib_signature_ctx *)params->ctx;

	key_desc.id = get_key_id_from((struct libobj_obj *)ctx->hkey, rsa_pair);

	smw_args.subsystem_name = devinfo->name;
	smw_args.key_descriptor = &key_desc;

	return op_msign_common(&smw_args, entry, params, SMW_RSA_PSS_SIGN_TYPE);
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
	struct smw_tlv key_attr = { 0 };
	struct smw_tlv allowed_algos = { 0 };
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

	ret = build_key_allowed_algos(&allowed_algos, slotid, obj);
	if (ret != CKR_OK)
		goto end;

	ret = args_attrs_key_policy(&key_attr, obj, &allowed_algos);
	if (ret != CKR_OK)
		goto end;

	imp_args.subsystem_name = devinfo->name;
	imp_args.key_descriptor = &key;

	ret = args_attr_import_key(&key_attr, obj);
	if (ret != CKR_OK)
		goto end;

	imp_args.key_attributes_list = (unsigned char *)key_attr.string;
	imp_args.key_attributes_list_length = key_attr.length;

	status = smw_import_key(&imp_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Import Key on %s status %d return %ld", devinfo->name,
		  status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

end:
	tlv_encode_free(&allowed_algos);
	tlv_encode_free(&key_attr);

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

	DBG_TRACE("RNG on %s status %d return %ld", devinfo->name, status, ret);
	return ret;
}

static smw_cipher_mode_t get_cipher_mode(CK_MECHANISM_TYPE mech_type)
{
	smw_cipher_mode_t mode = NULL;
	unsigned int i = 0;

	for (; i < ARRAY_SIZE(cipher_algos); i++) {
		if (mech_type == cipher_algos[i].mech_type) {
			mode = cipher_algos[i].cipher_mode;
			break;
		}
	}

	return mode;
}

static CK_RV info_mcipher_common(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
				 struct mentry *entry,
				 CK_MECHANISM_INFO_PTR info,
				 struct smw_cipher_info cipher_info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo = NULL_PTR;

	DBG_TRACE("info of 0x%lx cipher mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * Global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = 0;

	cipher_info.mode = get_cipher_mode(entry->type);

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

static void check_mcipher_common(CK_SLOT_ID slotid, const char *subsystem,
				 struct mgroup *mgroup,
				 struct smw_cipher_info info)
{
	enum smw_status_code status = SMW_STATUS_OK;
	unsigned int idx;
	CK_FLAGS slot_flag = 0;
	struct mentry *entry = NULL_PTR;

	/*
	 * Slot flag is set if:
	 * encryption or decryption operation is supported
	 */

	slot_flag = BIT(slotid);

	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		info.mode = get_cipher_mode(entry->type);
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

static CK_RV cipher(struct lib_cipher_params *params,
		    struct smw_cipher_init_args *smw_init_args,
		    struct smw_cipher_data_args *smw_data_args)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;
	struct smw_cipher_args smw_args = { 0 };
	struct smw_op_context *op_ctx = NULL;

	struct lib_cipher_ctx *ctx = NULL_PTR;

	ctx = params->ctx;

	smw_args.data = *smw_data_args;
	smw_args.init = *smw_init_args;

	switch (params->state) {
	case OP_ONE_SHOT:
		status = smw_cipher(&smw_args);
		break;

	case OP_UPDATE:
		if (ctx->current_state == OP_INIT) {
			op_ctx = calloc(1, sizeof(*op_ctx));
			if (!op_ctx) {
				status = SMW_STATUS_ALLOC_FAILURE;
				goto end;
			}

			smw_init_args->context = op_ctx;
			status = smw_cipher_init(smw_init_args);
			if (status == SMW_STATUS_OK) {
				ctx->context = smw_init_args->context;
				smw_data_args->context = smw_init_args->context;
				status = smw_cipher_update(smw_data_args);
			}

		} else if (ctx->current_state == OP_UPDATE) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_cipher_update(smw_data_args);
		}

		break;

	case OP_FINAL:
		if (ctx->context) {
			smw_data_args->context =
				(struct smw_op_context *)ctx->context;
			status = smw_cipher_final(smw_data_args);
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

	/**
	 * Release the smw op context if either of the below condition is met.
	 * 1. if the final operation is successful and the
	 * output buffer length is 0 (smw_cipher_final function
	 * terminates the operation, if output buffer length is 0.)
	 * 2.if the final operation is successful and
	 * the pointer to output buffer is not null.
	 */
	if (status == SMW_STATUS_OK && params->state == OP_FINAL) {
		if (params->poutput || params->output_length == 0) {
			if (ctx->context) {
				free(ctx->context);
				ctx->context = NULL_PTR;
			}

			goto end;
		}
	}

end:

	ret = smw_status_to_ck_rv(status);
	DBG_TRACE("%s on subsystem %s SMW status = 0x%x return = 0x%lx",
		  params->op_flag == CKF_ENCRYPT ? ENCRYPT_STR : DECRYPT_STR,
		  smw_init_args->subsystem_name, status, ret);
	return ret;
}

static CK_RV set_smw_init_args(struct lib_cipher_ctx *ctx,
			       struct smw_cipher_init_args **smw_init_args,
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
		(*smw_init_args)->nb_keys = 2;
		*key_buffer =
			calloc((*smw_init_args)->nb_keys, sizeof(**key_buffer));
		if (!*key_buffer)
			return ret;

	} else {
		(*smw_init_args)->nb_keys = 1;
	}

	if (is_xts) {
		if (SET_OVERFLOW(ctx->key_len / 2, key_length))
			return CKR_ARGUMENTS_BAD;

		(*key_buffer)[0].gen.private_data = &ctx->key_value[0];
		(*key_buffer)[1].gen.private_data = &ctx->key_value[key_length];

		for (; i < (*smw_init_args)->nb_keys; i++) {
			(*key_buffer)[i].gen.private_length = key_length;
			key_desc_ptr[i].buffer = &(*key_buffer)[i];
			key_desc_ptr[i].type_name = "AES";
			key_desc_ptr[i].security_size =
				BYTES_TO_BITS(key_length);
		}

	} else {
		key_desc_ptr[0].id =
			get_key_id_from((struct libobj_obj *)ctx->hkey, cipher);
	}

	for (i = 0; i < (*smw_init_args)->nb_keys; i++)
		(*keys_desc)[i] = &key_desc_ptr[i];

	(*smw_init_args)->keys_desc = *keys_desc;
	(*smw_init_args)->subsystem_name = subsystem_name;
	(*smw_init_args)->mode_name = get_cipher_mode(ctx->cipher_mech);
	(*smw_init_args)->iv = ctx->iv;

	if (SET_OVERFLOW(ctx->iv_length, (*smw_init_args)->iv_length))
		return CKR_ARGUMENTS_BAD;

	DBG_TRACE("Cipher mode = %s", (*smw_init_args)->mode_name);

	if (op_flag == CKF_ENCRYPT)
		(*smw_init_args)->operation_name = ENCRYPT_STR;
	else
		(*smw_init_args)->operation_name = DECRYPT_STR;

	return CKR_OK;
}

static CK_RV op_mcipher_common(CK_SLOT_ID slotid, void *args)
{
	CK_RV ret = CKR_OK;

	const struct libdev *devinfo = NULL_PTR;
	struct lib_cipher_ctx *ctx = NULL_PTR;
	struct lib_cipher_params *params = NULL_PTR;

	struct smw_keypair_buffer *key_buffer = NULL_PTR;
	struct smw_cipher_init_args smw_init_args = { 0 };
	struct smw_cipher_init_args *smw_init_args_ptr = NULL_PTR;
	struct smw_cipher_data_args smw_data_args = { 0 };
	struct smw_key_descriptor *keys_desc[2] = { NULL_PTR };
	struct smw_key_descriptor key_descriptor[2] = { 0 };
	struct smw_key_descriptor **keys_desc_ptr = NULL_PTR;

	keys_desc_ptr = keys_desc;
	smw_init_args_ptr = &smw_init_args;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	params = (struct lib_cipher_params *)args;
	ctx = params->ctx;

	if ((params->state == OP_ONE_SHOT || OP_INIT) ||
	    (ctx->current_state == OP_INIT && params->state == OP_UPDATE)) {
		if (set_smw_init_args(ctx, &smw_init_args_ptr, &key_buffer,
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

static CK_RV info_mcipher_aes(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	struct smw_cipher_info cipher_info = { 0 };

	DBG_TRACE("Return info of 0x%lx cipher mechanism", type);

	cipher_info.key_type_name = AES_STR;

	ret = info_mcipher_common(slotid, type, entry, info, cipher_info);

	return ret;
}

static void check_mcipher_aes(CK_SLOT_ID slotid, const char *subsystem,
			      struct mgroup *mgroup)
{
	struct smw_cipher_info info = { 0 };

	info.key_type_name = AES_STR;

	check_mcipher_common(slotid, subsystem, mgroup, info);
}

static CK_RV op_mcipher_aes(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	(void)entry;
	return op_mcipher_common(slotid, args);
}

static CK_RV info_mcipher_des(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			      struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	struct smw_cipher_info cipher_info = { 0 };

	DBG_TRACE("Return info of 0x%lx cipher mechanism", type);

	cipher_info.key_type_name = DES_STR;

	ret = info_mcipher_common(slotid, type, entry, info, cipher_info);

	return ret;
}

static void check_mcipher_des(CK_SLOT_ID slotid, const char *subsystem,
			      struct mgroup *mgroup)
{
	struct smw_cipher_info info = { 0 };

	info.key_type_name = DES_STR;

	check_mcipher_common(slotid, subsystem, mgroup, info);
}

static CK_RV op_mcipher_des(CK_SLOT_ID slotid, struct mentry *entry, void *args)
{
	(void)entry;
	return op_mcipher_common(slotid, args);
}

static CK_RV info_mcipher_des3(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			       struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	struct smw_cipher_info cipher_info = { 0 };

	DBG_TRACE("Return info of 0x%lx cipher mechanism", type);

	cipher_info.key_type_name = DES3_STR;

	ret = info_mcipher_common(slotid, type, entry, info, cipher_info);

	return ret;
}

static void check_mcipher_des3(CK_SLOT_ID slotid, const char *subsystem,
			       struct mgroup *mgroup)
{
	struct smw_cipher_info info = { 0 };

	info.key_type_name = DES3_STR;

	check_mcipher_common(slotid, subsystem, mgroup, info);
}

static CK_RV op_mcipher_des3(CK_SLOT_ID slotid, struct mentry *entry,
			     void *args)
{
	(void)entry;
	return op_mcipher_common(slotid, args);
}

CK_RV libdev_cancel_operation(void **context)
{
	CK_RV ret = CKR_OK;
	enum smw_status_code status = SMW_STATUS_OK;

	status = smw_cancel_operation((struct smw_op_context *)*context);
	ret = smw_status_to_ck_rv(status);

	if (*context) {
		free(*context);
		*context = NULL_PTR;
	}

	DBG_TRACE(" smw cancel operation ret = %lx\n", ret);
	return ret;
}
