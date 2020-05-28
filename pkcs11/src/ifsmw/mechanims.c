// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include "smw_config.h"
#include "smw_status.h"

#include "lib_context.h"
#include "lib_device.h"
#include "pkcs11smw.h"

#include "trace.h"

#include "local.h"

struct mgroup;

/*
 * Function prototype to check if all mechanism of a group
 * are supported by a SMW subsystem
 */
#define FUNC_MECH_CHECK(name)                                                  \
	void(name)(CK_SLOT_ID slotid, const char *subsystem,                   \
		   struct mgroup *mgroup)
#define FUNC_MECH_CHECK_PTR(name) FUNC_MECH_CHECK(*(name))

static FUNC_MECH_CHECK(check_mdigest);

/**
 * struct mentry - Definition of a mechanism supported by each device
 * @name: Name of the algorithm used in SMW
 * @type: Cryptoki Mechanism type
 * @slot_flag: Bit mask flag of a device supporting the mechanism
 */
struct mentry {
	const char *name;
	CK_MECHANISM_TYPE type;
	CK_FLAGS slot_flag;
};

/**
 * struct mgroup - Definition of a mechanism group
 * @number: Number of mechanisms in the group
 * @mechanism: Mechanism entry
 *
 * Mechanisms are grouped by class of cryptographic
 */
struct mgroup {
	unsigned int number;
	struct mentry *mechanism;

	FUNC_MECH_CHECK_PTR(check);
	FUNC_MECH_INFO_PTR(*info);
};

#define M_INIT(name, id)                                                       \
	{                                                                      \
		STR(name), CKM_##id, 0,                                        \
	}

#define M_GROUP(nb, grp)                                                       \
	{                                                                      \
		.number = nb, .mechanism = grp, .check = check_##grp,          \
		.info = info_##grp,                                            \
	}

/*
 * Digest mechanisms
 */
static struct mentry mdigest[] = {
	M_INIT(SHA1, SHA_1),	M_INIT(SHA224, SHA224), M_INIT(SHA256, SHA256),
	M_INIT(SHA384, SHA384), M_INIT(SHA512, SHA512),
};

FUNC_MECH_INFO_PTR(info_mdigest[]) = { hsm_info_mdigest, optee_info_mdigest };

/*
 * All SMW mechanisms
 */
static struct mgroup smw_mechanims[] = { M_GROUP(ARRAY_SIZE(mdigest), mdigest),
					 { .number = 0 } };

CK_RV libdev_get_mechanisms(CK_SLOT_ID slotid,
			    CK_MECHANISM_TYPE_PTR mechanismlist,
			    CK_ULONG_PTR count)
{
	CK_RV ret;
	struct libdevice *devices;
	struct mgroup *group;
	struct mentry *entry;
	unsigned int idx;
	unsigned int nb_devices;
	CK_MECHANISM_TYPE_PTR item = mechanismlist;
	CK_ULONG nb_mechanisms = 0;
	CK_FLAGS slot_flag;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	nb_devices = libdev_get_nb_devinfo();
	if (slotid >= nb_devices)
		return CKR_SLOT_ID_INVALID;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	/* Check if the Slot is present */
	if (!devices[slotid].slot.flags & CKF_TOKEN_PRESENT) {
		DBG_TRACE("Slot %lu is not present", slotid);
		return CKR_TOKEN_NOT_PRESENT;
	}

	DBG_TRACE("Get list of mechanisms for slot %lu", slotid);

	slot_flag = BIT(slotid);
	for (group = smw_mechanims; group->number; group++) {
		DBG_TRACE("Group %p has %u entries", group, group->number);
		for (idx = 0, entry = group->mechanism; idx < group->number;
		     idx++, entry++) {
			DBG_TRACE("%s - 0x%lx", entry->name, entry->type);
			if (entry->slot_flag & slot_flag) {
				DBG_TRACE("%s supported", entry->name);
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
	struct libdevice *devices;
	struct mgroup *group;
	struct mentry *entry;
	unsigned int idx;
	unsigned int nb_devices;
	CK_FLAGS slot_flag;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	nb_devices = libdev_get_nb_devinfo();
	if (slotid >= nb_devices)
		return CKR_SLOT_ID_INVALID;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	/* Check if the Slot is present */
	if (!devices[slotid].slot.flags & CKF_TOKEN_PRESENT) {
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
					DBG_TRACE("%lu not supported", type);
					return CKR_MECHANISM_INVALID;
				}

				return group->info[slotid](type, info);
			}
		}
	}

	return CKR_MECHANISM_INVALID;
}

static FUNC_MECH_CHECK(check_mdigest)
{
	int status;
	unsigned int idx;
	struct mentry *entry;
	CK_FLAGS slot_flag;

	slot_flag = BIT(slotid);
	for (idx = 0, entry = mgroup->mechanism; idx < mgroup->number;
	     idx++, entry++) {
		status = smw_config_subsystem_check_digest(subsystem,
							   entry->name);
		DBG_TRACE("%s digest %s: %d", subsystem, entry->name, status);
		if (status == SMW_STATUS_OK)
			SET_BITS(entry->slot_flag, slot_flag);
	}
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
