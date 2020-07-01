// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib_context.h"
#include "lib_device.h"

#include "trace.h"

/**
 * clean_token() - Clean the token
 * @device: reference to the slot's device objects
 *
 * TODO: implementation of the token clean (destroy object that
 * can be destroyed)
 *
 * return:
 * CKR_OK   Success
 */
static CK_RV clean_token(struct libdevice *device)
{
	CLEAR_BITS(device->token.flags, CKF_TOKEN_INITIALIZED);
	return CKR_OK;
}

CK_RV libdev_get_slotinfo(CK_SLOT_ID slotid, CK_SLOT_INFO_PTR pinfo)
{
	CK_RV ret;
	struct libdevice *devices;
	const struct libdev *devinfo;
	size_t len;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	len = strlen(devinfo->description);
	memcpy(pinfo->slotDescription, devinfo->description,
	       MIN(sizeof(pinfo->slotDescription), len));

	DBG_TRACE("Slot Description (%zu) bytes: %s", len,
		  devinfo->description);

	if (len < sizeof(pinfo->slotDescription))
		memset(pinfo->slotDescription + len, ' ',
		       sizeof(pinfo->slotDescription) - len);

	len = strlen(devinfo->manufacturer);
	memcpy(pinfo->manufacturerID, devinfo->manufacturer,
	       MIN(sizeof(pinfo->manufacturerID), len));

	DBG_TRACE("Manufacturer (%zu) bytes: %s", len, devinfo->manufacturer);

	if (len < sizeof(pinfo->manufacturerID))
		memset(pinfo->manufacturerID + len, ' ',
		       sizeof(pinfo->manufacturerID) - len);

	pinfo->flags = devinfo->flags_slot | devices[slotid].slot.flags;

	if (devinfo->flags_slot & CKF_HW_SLOT) {
		pinfo->hardwareVersion = devinfo->version;
		pinfo->firmwareVersion.major = 0;
		pinfo->firmwareVersion.minor = 0;
	} else {
		pinfo->hardwareVersion.major = 0;
		pinfo->hardwareVersion.minor = 0;
		pinfo->firmwareVersion = devinfo->version;
	}

	return CKR_OK;
}

CK_RV libdev_get_tokeninfo(CK_SLOT_ID slotid, CK_TOKEN_INFO_PTR pinfo)
{
	CK_RV ret;
	struct libdevice *devices;
	const struct libdev *devinfo;
	time_t now;
	struct tm *tminfo;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	memcpy(pinfo->label, devices[slotid].token.label, sizeof(pinfo->label));
	DBG_TRACE("Token label: %.*s", (int)sizeof(pinfo->label), pinfo->label);

	util_copy_str_to_utf8(pinfo->manufacturerID,
			      sizeof(pinfo->manufacturerID),
			      devinfo->manufacturer);
	DBG_TRACE("Manufacturer: %.*s", (int)sizeof(pinfo->manufacturerID),
		  pinfo->manufacturerID);

	util_copy_str_to_utf8(pinfo->model, sizeof(pinfo->model),
			      devinfo->model);
	DBG_TRACE("Model: %.*s", (int)sizeof(pinfo->model), pinfo->model);

	util_copy_str_to_utf8(pinfo->serialNumber, sizeof(pinfo->serialNumber),
			      devinfo->serial);
	DBG_TRACE("Serial Number: %.*s", (int)sizeof(pinfo->serialNumber),
		  pinfo->serialNumber);

	pinfo->flags = devinfo->flags_token | devices[slotid].token.flags;
	pinfo->ulMaxSessionCount = devices[slotid].token.max_session;
	pinfo->ulSessionCount = devices[slotid].token.session_count;
	pinfo->ulMaxRwSessionCount = devices[slotid].token.max_rw_session;
	pinfo->ulRwSessionCount = devices[slotid].token.rw_session_count;
	pinfo->ulMaxPinLen = devices[slotid].token.max_pin_len;
	pinfo->ulMinPinLen = devices[slotid].token.min_pin_len;
	pinfo->ulTotalPublicMemory = devices[slotid].token.total_pub_mem;
	pinfo->ulFreePublicMemory = devices[slotid].token.free_pub_mem;
	pinfo->ulTotalPrivateMemory = devices[slotid].token.total_priv_mem;
	pinfo->ulFreePrivateMemory = devices[slotid].token.free_priv_mem;

	if (devinfo->flags_slot & CKF_HW_SLOT) {
		pinfo->hardwareVersion = devinfo->version;
		pinfo->firmwareVersion.major = 0;
		pinfo->firmwareVersion.minor = 0;
	} else {
		pinfo->hardwareVersion.major = 0;
		pinfo->hardwareVersion.minor = 0;
		pinfo->firmwareVersion = devinfo->version;
	}

	/* Set the current time */
	now = time((time_t *)NULL);
	if (now == (time_t)-1)
		return CKR_FUNCTION_FAILED;

	tminfo = localtime(&now);
	if (!tminfo)
		return CKR_FUNCTION_FAILED;

	(void)strftime((char *)pinfo->utcTime, sizeof(pinfo->utcTime),
		       "%Y%m%d%H%M%S", tminfo);
	pinfo->utcTime[14] = '0';
	pinfo->utcTime[15] = '0';

	return CKR_OK;
}

CK_RV libdev_get_slots(CK_ULONG_PTR count, CK_SLOT_ID_PTR slotlist)
{
	CK_RV ret;
	struct libdevice *devices;
	CK_SLOT_ID_PTR item = slotlist;
	CK_ULONG nb_slots = 0;
	unsigned int nb_devices;
	unsigned int idx;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	nb_devices = libdev_get_nb_devinfo();
	DBG_TRACE("Number of devices %u", nb_devices);

	if (slotlist && *count < nb_devices)
		return CKR_BUFFER_TOO_SMALL;

	/* Update the slot presence */
	libdev_set_present(devices);

	for (idx = 0; idx < nb_devices; idx++) {
		nb_slots++;
		if (item) {
			if (*count < nb_slots)
				return CKR_BUFFER_TOO_SMALL;

			*item = idx;
			item++;
		}
	}

	DBG_TRACE("Return %lu slots", nb_slots);
	*count = nb_slots;

	return CKR_OK;
}

CK_RV libdev_get_slots_present(CK_ULONG_PTR count, CK_SLOT_ID_PTR slotlist)
{
	CK_RV ret;
	struct libdevice *devices;
	CK_SLOT_ID_PTR item = slotlist;
	CK_ULONG nb_slots = 0;
	unsigned int nb_devices;
	unsigned int idx;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	nb_devices = libdev_get_nb_devinfo();

	/* Update the slot presence */
	libdev_set_present(devices);

	for (idx = 0; idx < nb_devices; idx++) {
		if (devices[idx].slot.flags & CKF_TOKEN_PRESENT) {
			DBG_TRACE("Slot %u is Present", idx);
			nb_slots++;
			if (item) {
				if (*count < nb_slots)
					return CKR_BUFFER_TOO_SMALL;

				*item = idx;
				item++;
			}
		}
	}

	DBG_TRACE("Return %lu slots", nb_slots);
	*count = nb_slots;

	return CKR_OK;
}

CK_RV libdev_init_token(CK_SLOT_ID slotid, CK_UTF8CHAR_PTR label)
{
	CK_RV ret;
	struct libdevice *devices;
	unsigned int nb_devices;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	nb_devices = libdev_get_nb_devinfo();
	if (slotid >= nb_devices)
		return CKR_SLOT_ID_INVALID;

	if (!(devices[slotid].slot.flags & CKF_TOKEN_PRESENT))
		return CKR_TOKEN_NOT_PRESENT;

	/*
	 * If there is a session opened on this token, it can't be
	 * initialized or re-initialized.
	 */
	if (devices[slotid].token.session_count)
		return CKR_SESSION_EXISTS;

	/*
	 * If token already initialized, need to:
	 *  - destroyed all associated objects that can be destroyed
	 *  - re-initialized the token
	 */
	if (!(devices[slotid].token.flags & CKF_TOKEN_INITIALIZED)) {
		ret = clean_token(&devices[slotid]);
		if (ret != CKR_OK)
			return ret;
	}

	ret = libdev_mechanisms_init(slotid);
	if (ret != CKR_OK)
		return ret;

	memcpy(devices[slotid].token.label, label,
	       sizeof(devices[slotid].token.label));

	SET_BITS(devices[slotid].token.flags, CKF_TOKEN_INITIALIZED);

	return CKR_OK;
}

CK_RV libdev_initialize(struct libctx *libctx)
{
	unsigned int nb_devices;

	if (!libctx)
		return CKR_GENERAL_ERROR;

	nb_devices = libdev_get_nb_devinfo();
	libctx->devices = calloc(1, nb_devices * sizeof(*libctx->devices));

	if (!libctx->devices)
		return CKR_HOST_MEMORY;

	return CKR_OK;
}