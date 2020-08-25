// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include "smw_config.h"
#include "smw_status.h"

#include "dev_config.h"
#include "lib_context.h"
#include "lib_device.h"
#include "pkcs11smw.h"

#include "trace.h"

struct mgroup;
struct mentry;

static void check_mdigest(CK_SLOT_ID slotid, const char *subsystem,
			  struct mgroup *mgroup);
static CK_RV info_mdigest(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			  struct mentry *entry, CK_MECHANISM_INFO_PTR info);
static void check_meckeygen(CK_SLOT_ID slotid, const char *subsystem,
			    struct mgroup *mgroup);
static CK_RV info_meckeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info);

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
 * @info: Function getting SMW informaton on mechanism
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
		.info = info_##grp,                                            \
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
 * All SMW mechanisms
 */
static struct mgroup smw_mechanims[] = {
	M_GROUP(ARRAY_SIZE(mdigest), mdigest),
	M_GROUP(ARRAY_SIZE(meckeygen), meckeygen),
	{ 0 },
};

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
	struct libdevice *dev;
	struct mgroup *group;
	struct mentry *entry;
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
	for (group = smw_mechanims; group->number; group++) {
		for (idx = 0, entry = group->mechanism; idx < group->number;
		     idx++, entry++) {
			if (entry->type == type) {
				DBG_TRACE("Found mechanism 0x%lx", type);
				if (!(entry->slot_flag & slot_flag)) {
					DBG_TRACE("0x%lx not supported", type);
					return CKR_MECHANISM_INVALID;
				}

				return group->info(slotid, type, entry, info);
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

static void check_meckeygen(CK_SLOT_ID slotid, const char *subsystem,
			    struct mgroup *mgroup)
{
	int status;
	unsigned int idx;
	unsigned int idx_algo;
	struct mentry *entry;
	CK_FLAGS slot_flag;
	struct smw_key_info info = { 0 };
	char **name;

	slot_flag = BIT(slotid);
	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		name = entry->smw_algo;
		for (idx_algo = 0; idx_algo < entry->nb_smw_algo; idx_algo++) {
			info.key_type_name = name[idx_algo];

			status =
				smw_config_check_generate_key(subsystem, &info);
			DBG_TRACE("%s EC Key Generate %s: %d", subsystem,
				  name[idx_algo], status);

			if (status == SMW_STATUS_OK)
				SET_BITS(entry->slot_flag, slot_flag);
		}
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

static CK_RV info_meckeygen(CK_SLOT_ID slotid, CK_MECHANISM_TYPE type,
			    struct mentry *entry, CK_MECHANISM_INFO_PTR info)
{
	CK_RV ret = CKR_OK;
	int status;
	const struct libdev *devinfo;
	unsigned int idx;
	struct smw_key_info keyinfo = { 0 };
	char **name;

	DBG_TRACE("Return info of 0x%lx EC Key Generate mechanism", type);

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	/*
	 * EC Key Generate global settings.
	 */
	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags =
		CKF_EC_OID | CKF_EC_CURVENAME | CKF_EC_F_P | CKF_EC_UNCOMPRESS;

	name = entry->smw_algo;
	for (idx = 0; idx < entry->nb_smw_algo; idx++) {
		keyinfo.key_type_name = name[idx];
		keyinfo.security_size = 0;

		status = smw_config_check_generate_key(devinfo->name, &keyinfo);
		DBG_TRACE("%s EC Key Generate %s: %d", devinfo->name, name[idx],
			  status);

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
