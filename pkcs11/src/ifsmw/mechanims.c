// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include "smw_config.h"
#include "smw_status.h"
#include "smw_crypto.h"

#include "dev_config.h"
#include "lib_context.h"
#include "lib_device.h"
#include "lib_session.h"
#include "lib_digest.h"
#include "libobj_types.h"
#include "pkcs11smw.h"
#include "types.h"
#include "lib_sign_verify.h"

#include "args_attr.h"
#include "key_desc.h"
#include "tlv_encode.h"

#include "trace.h"

#define SMW_RSA_PKCS1_V1_5_SIGN_TYPE "RSASSA-PKCS1-V1_5"
#define SMW_RSA_PSS_SIGN_TYPE	     "RSASSA-PSS"

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

const char *smw_ec_name[] = { "NIST", "BRAINPOOL_R1", "BRAINPOOL_T1" };

/**
 * struct mentry - Definition of a mechanism supported by each device
 * @type: Cryptoki Mechanism type
 * @slot_flag: Bit mask flag of a device supporting the mechanism
 * @nb_smw_algo: Number of SMW algorithm for this mechanism
 * @smw_algo: Mechanism's algorithm(s) definition corresponding to SMW
 */
struct mentry {
	CK_MECHANISM_TYPE type;
	CK_FLAGS slot_flag;
	unsigned int nb_smw_algo;
	void *smw_algo;
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

/* Macro filling a struct mentry for a hash algo */
#define M_ALGO_SINGLE(name, id)                                                \
	{                                                                      \
		.type = CKM_##id, .slot_flag = 0, .nb_smw_algo = 1,            \
		.smw_algo = STR(name),                                         \
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
	M_ALGO_SINGLE(SHA1, SHA_1),    M_ALGO_SINGLE(SHA224, SHA224),
	M_ALGO_SINGLE(SHA256, SHA256), M_ALGO_SINGLE(SHA384, SHA384),
	M_ALGO_SINGLE(SHA512, SHA512),
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
	M_ALGO_SINGLE(AES, AES_KEY_GEN),
	M_ALGO_SINGLE(DES, DES_KEY_GEN),
	M_ALGO_SINGLE(DES3, DES3_KEY_GEN),
	M_ALGO_SINGLE(RSA, RSA_PKCS_KEY_PAIR_GEN),
};

/*
 * Signature mechanism
 */
static struct mentry msign_ecdsa[] = {
	M_ALGO_SINGLE(, ECDSA),
	M_ALGO_SINGLE(SHA1, ECDSA_SHA1),
	M_ALGO_SINGLE(SHA224, ECDSA_SHA224),
	M_ALGO_SINGLE(SHA256, ECDSA_SHA256),
	M_ALGO_SINGLE(SHA384, ECDSA_SHA384),
	M_ALGO_SINGLE(SHA512, ECDSA_SHA512),
};

static struct mentry msign_rsa_pkcs_v1_5[] = {
	M_ALGO_SINGLE(, RSA_PKCS),
	M_ALGO_SINGLE(SHA1, SHA1_RSA_PKCS),
	M_ALGO_SINGLE(SHA224, SHA224_RSA_PKCS),
	M_ALGO_SINGLE(SHA256, SHA256_RSA_PKCS),
	M_ALGO_SINGLE(SHA384, SHA384_RSA_PKCS),
	M_ALGO_SINGLE(SHA512, SHA512_RSA_PKCS),
};

static struct mentry msign_rsa_pss[] = {
	M_ALGO_SINGLE(, RSA_PKCS_PSS),
	M_ALGO_SINGLE(SHA1, SHA1_RSA_PKCS_PSS),
	M_ALGO_SINGLE(SHA224, SHA224_RSA_PKCS_PSS),
	M_ALGO_SINGLE(SHA256, SHA256_RSA_PKCS_PSS),
	M_ALGO_SINGLE(SHA384, SHA384_RSA_PKCS_PSS),
	M_ALGO_SINGLE(SHA512, SHA512_RSA_PKCS_PSS),
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
	{ 0 },
};

#define GET_ALGO_NAME(entry, idx)                                              \
	({                                                                     \
		__typeof__(entry) _entry = entry;                              \
		(_entry->nb_smw_algo > 1) ?                                    \
			((const char **)_entry->smw_algo)[idx] :               \
			_entry->smw_algo;                                      \
	})

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
static CK_RV smw_status_to_ck_rv(int status)
{
	switch (status) {
	case SMW_STATUS_OK:
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
	CK_RV ret;
	struct libdevice *dev;
	struct mgroup *grp;
	struct mentry *ent;
	unsigned int idx;
	CK_FLAGS slot_flag;

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

	/* Check if the Slot is present */
	if (!dev->slot.flags & CKF_TOKEN_PRESENT) {
		DBG_TRACE("Slot %lu is not present", slotid);
		return CKR_TOKEN_NOT_PRESENT;
	}

	DBG_TRACE("Search for mechanism %lu", type);

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
	int status;
	unsigned int idx;
	struct mentry *entry;
	CK_FLAGS slot_flag;

	slot_flag = BIT(slotid);
	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
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
	int status;
	unsigned int idx;
	unsigned int idx_algo;
	struct mentry *entry;
	CK_FLAGS slot_flag;
	struct smw_key_info info = { 0 };

	slot_flag = BIT(slotid);
	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
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
	CK_RV ret;
	int status;
	const struct libdev *devinfo;
	struct libdig_params *params = args;
	struct smw_hash_args hash_args = { 0 };

	DBG_TRACE("Digest mechanism");
	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	hash_args.subsystem_name = devinfo->name;
	hash_args.algo_name = GET_ALGO_NAME(entry, 0);
	hash_args.input = params->pData;
	hash_args.input_length = params->ulDataLen;
	hash_args.output = params->pDigest;
	hash_args.output_length = *params->pulDigestLen;

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
	int status;
	const struct libdev *devinfo;
	unsigned int idx;
	struct smw_key_info keyinfo = { 0 };

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	for (idx = 0; idx < entry->nb_smw_algo; idx++) {
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

static CK_RV op_keygen_common(CK_SLOT_ID slotid, struct libobj_obj *obj)
{
	CK_RV ret;
	const struct libdev *devinfo;
	int status;
	struct smw_tlv key_attr = { 0 };
	struct smw_generate_key_args gen_args = { 0 };
	struct smw_key_descriptor key = { 0 };

	DBG_TRACE("Common Generate Key mechanism");
	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	ret = key_desc_setup(&key, obj);
	if (ret != CKR_OK)
		return ret;

	gen_args.subsystem_name = devinfo->name;
	gen_args.key_descriptor = &key;

	ret = args_attr_generate_key(&key_attr, obj);
	if (ret != CKR_OK)
		goto end;

	gen_args.key_attributes_list = (const unsigned char *)key_attr.string;
	gen_args.key_attributes_list_length = key_attr.length;

	status = smw_generate_key(&gen_args);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Generate Key on %s status %d return %ld", devinfo->name,
		  status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

end:
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
	int status;
	unsigned int idx;
	unsigned int ecdsa_idx;
	struct smw_signature_info info = { 0 };
	struct mentry *entry;
	CK_FLAGS slot_flag;

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
	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		if (strlen(entry->smw_algo))
			info.hash_algo = entry->smw_algo;

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
	int status;
	unsigned int idx;
	CK_FLAGS slot_flag;
	struct mentry *entry;

	/*
	 * smw_config_check_sign() checks the key type, the hash algorithm
	 * (optional) and the signature type (optional).
	 *
	 * Slot flag is set if:
	 *  - sign or verify or both operations are supported
	 */

	info->key_type_name = "RSA";

	slot_flag = BIT(slotid);
	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		if (strlen(entry->smw_algo))
			info->hash_algo = entry->smw_algo;

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
	int status;
	CK_RV ret = CKR_OK;
	unsigned int ecdsa_idx;
	struct smw_signature_info sign_verify_info = { 0 };
	const struct libdev *devinfo;

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

	if (strlen(entry->smw_algo))
		sign_verify_info.hash_algo = entry->smw_algo;

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
	int status;
	CK_RV ret = CKR_OK;
	const struct libdev *devinfo;

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

	if (strlen(entry->smw_algo))
		sign_verify_info->hash_algo = entry->smw_algo;
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
	CK_RV ret;
	int status;
	unsigned int i;
	struct smw_tlv attr = { 0 };
	struct lib_signature_ctx *ctx = (struct lib_signature_ctx *)params->ctx;

	smw_args->message = params->pdata;
	smw_args->message_length = params->uldatalen;
	smw_args->signature = params->psignature;
	smw_args->signature_length = params->ulsignaturelen;

	/* Get hash algorithm */
	if (strlen(entry->smw_algo)) {
		smw_args->algo_name = entry->smw_algo;
	} else if (ctx->hash_mech) {
		for (i = 0; i < ARRAY_SIZE(mdigest); i++) {
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
		smw_args->attributes_list = (const unsigned char *)attr.string;
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
	const struct libdev *devinfo;
	struct lib_signature_ctx *ctx;
	struct lib_signature_params *params;
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
	const struct libdev *devinfo;
	struct lib_signature_ctx *ctx;
	struct lib_signature_params *params;
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
	const struct libdev *devinfo;
	struct lib_signature_ctx *ctx;
	struct lib_signature_params *params;
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
	CK_RV ret;
	struct libdevice *dev;
	struct mgroup *group;
	struct mentry *entry;
	unsigned int idx;
	CK_MECHANISM_TYPE_PTR item = mechanismlist;
	CK_ULONG nb_mechanisms = 0;
	CK_FLAGS slot_flag;

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
				nb_mechanisms++;
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
	CK_RV ret;
	struct mgroup *group;
	struct mentry *entry;

	ret = find_mechanism(slotid, type, &group, &entry);
	if (ret == CKR_OK)
		ret = group->info(slotid, type, entry, info);

	return ret;
}

CK_RV libdev_validate_mechanism(CK_SLOT_ID slotid, CK_MECHANISM_PTR mech,
				CK_FLAGS op_flag)
{
	CK_RV ret;
	CK_MECHANISM_INFO info;

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
	CK_RV ret;
	CK_SLOT_ID slotid;
	struct mgroup *group;
	struct mentry *entry;

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
	CK_RV ret;
	int status;
	CK_SLOT_ID slotid;
	const struct libdev *devinfo;
	struct smw_tlv key_attr = { 0 };
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

	imp_args.subsystem_name = devinfo->name;
	imp_args.key_descriptor = &key;

	ret = args_attr_import_key(&key_attr, obj);
	if (ret != CKR_OK)
		goto end;

	imp_args.key_attributes_list = (const unsigned char *)key_attr.string;
	imp_args.key_attributes_list_length = key_attr.length;

	status = smw_import_key(&imp_args);
	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Import Key on %s status %d return %ld", devinfo->name,
		  status, ret);

	if (ret == CKR_OK)
		key_desc_copy_key_id(obj, &key);

end:
	tlv_encode_free(&key_attr);

	return ret;
}

CK_RV libdev_delete_key(unsigned long long key_id)
{
	CK_RV ret;
	int status;
	struct smw_key_descriptor key_desc = { 0 };
	struct smw_delete_key_args key_args = { 0 };

	DBG_TRACE("Delete Key ID %llx", key_id);
	if (!key_id)
		return CKR_ARGUMENTS_BAD;

	key_desc.id = key_id;
	key_args.key_descriptor = &key_desc;
	status = smw_delete_key(&key_args);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("Delete Key status %d return %ld", status, ret);

	return ret;
}

CK_RV libdev_mechanisms_init(CK_SLOT_ID slotid)
{
	const struct libdev *devinfo;
	struct mgroup *group;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	for (group = smw_mechanims; group->number; group++)
		group->check(slotid, devinfo->name, group);

	return CKR_OK;
}

CK_RV libdev_rng(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pRandomData,
		 CK_ULONG ulRandomLen)
{
	CK_RV ret;
	int status;
	CK_SLOT_ID slotid;
	const struct libdev *devinfo;
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
	args.output_length = ulRandomLen;

	status = smw_rng(&args);

	ret = smw_status_to_ck_rv(status);

	DBG_TRACE("RNG on %s status %d return %ld", devinfo->name, status, ret);
	return ret;
}
