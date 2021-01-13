// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include <string.h>

#include "smw_config.h"
#include "smw_status.h"

#include "dev_config.h"
#include "lib_context.h"
#include "lib_device.h"
#include "lib_session.h"
#include "libobj_types.h"
#include "pkcs11smw.h"
#include "types.h"

#include "key_desc.h"
#include "tlv_encode.h"

#include "trace.h"

struct mgroup;
struct mentry;

static void check_mdigest(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mdigest(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mdigest(CK_SLOT_ID slotid, void *args);
static void check_meckeygen(CK_SLOT_ID slotid, const char *subsystem,
			    struct mgroup *mgroup);
static CK_RV info_meckeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_meckeygen(CK_SLOT_ID slotid, void *args);
static void check_mkeygen(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mkeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static CK_RV op_mkeygen(CK_SLOT_ID slotid, void *args);

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
	CK_RV (*op)(CK_SLOT_ID slotid, void *args);
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
 * AES Key Generate mechanism
 */
static struct mentry mkeygen[] = {
	M_ALGO_SINGLE(AES, AES_KEY_GEN),
	M_ALGO_SINGLE(DES, DES_KEY_GEN),
	M_ALGO_SINGLE(DES3, DES3_KEY_GEN),
};

/*
 * All SMW mechanisms
 */
static struct mgroup smw_mechanims[] = {
	M_GROUP(ARRAY_SIZE(mdigest), mdigest),
	M_GROUP(ARRAY_SIZE(meckeygen), meckeygen),
	M_GROUP(ARRAY_SIZE(mkeygen), mkeygen),
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
 * CKR_OK                        - Success
 */
static CK_RV smw_status_to_ck_rv(int status)
{
	switch (status) {
	case SMW_STATUS_OK:
		return CKR_OK;

	case SMW_STATUS_ALLOC_FAILURE:
		return CKR_DEVICE_MEMORY;

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

static CK_RV op_mdigest(CK_SLOT_ID slotid, void *args)
{
	(void)slotid;
	(void)args;

	return CKR_FUNCTION_FAILED;
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
	info->flags =
		CKF_EC_OID | CKF_EC_CURVENAME | CKF_EC_F_P | CKF_EC_UNCOMPRESS;

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
	info->flags = 0;

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

	if (is_token_obj(obj, storage)) {
		DBG_TRACE("Generate Persistent Key");
		ret = tlv_encode_boolean(&key_attr, "PERSISTENT");
		if (ret != CKR_OK)
			goto end;

		gen_args.key_attributes_list =
			(const unsigned char *)key_attr.string;
		gen_args.key_attributes_list_length = key_attr.length;
	}

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

static CK_RV op_meckeygen(CK_SLOT_ID slotid, void *args)
{
	DBG_TRACE("Generate EC Key mechanism");
	return op_keygen_common(slotid, args);
}

static CK_RV op_mkeygen(CK_SLOT_ID slotid, void *args)
{
	DBG_TRACE("Generate Key mechanism");
	return op_keygen_common(slotid, args);
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

CK_RV libdev_validate_mechanism(CK_SLOT_ID slotid, CK_MECHANISM_PTR mech)
{
	return find_mechanism(slotid, mech->mechanism, NULL, NULL);
}

CK_RV libdev_operate_mechanism(CK_SESSION_HANDLE hsession,
			       CK_MECHANISM_PTR mech, void *args)
{
	CK_RV ret;
	CK_SLOT_ID slotid;
	struct mgroup *group;

	/* Before calling SMW, call the application callback */
	ret = libsess_callback(hsession, CKN_SURRENDER);
	if (ret != CKR_OK)
		return ret;

	ret = libsess_get_slotid(hsession, &slotid);
	if (ret != CKR_OK)
		return ret;

	ret = find_mechanism(slotid, mech->mechanism, &group, NULL);
	if (ret == CKR_OK)
		ret = group->op(slotid, args);

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

	if (is_token_obj(obj, storage)) {
		DBG_TRACE("Import Persistent Key");
		ret = tlv_encode_boolean(&key_attr, "PERSISTENT");
		if (ret != CKR_OK)
			goto end;

		imp_args.key_attributes_list =
			(const unsigned char *)key_attr.string;
		imp_args.key_attributes_list_length = key_attr.length;
	}

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
