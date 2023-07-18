// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib_context.h"
#include "lib_device.h"
#include "lib_mutex.h"
#include "lib_object.h"
#include "lib_session.h"

#include "trace.h"

/**
 * clean_token() - Clean the token
 * @device: reference to the slot's device objects
 * @slotid: Token ID
 *
 * Close all Token's sessions.
 * If success clear the Token Initialization flag.
 *
 * return:
 * CKR_CRYPTOKI_NOT_INITIALIZED  - Context not initialized
 * CKR_GENERAL_ERROR             - No slot defined
 * CKR_SLOT_ID_INVALID           - Slot ID is not valid
 * CKR_OK                        - Success
 */
static CK_RV clean_token(struct libdevice *device, CK_SLOT_ID slotid)
{
	CK_RV ret = CKR_OK;

	if (!(device->token.flags & CKF_TOKEN_INITIALIZED))
		return ret;

	ret = libsess_close_all(slotid);
	DBG_TRACE("Token #%lu close all sessions ret %lu", slotid, ret);

	if (ret == CKR_OK) {
		ret = libobj_list_destroy(&device->objects);
		if (ret == CKR_OK)
			CLEAR_BITS(device->token.flags, CKF_TOKEN_INITIALIZED);
	}

	return ret;
}

/**
 * init_device_info() - Initialize the device information
 * @device: reference to the slot's device objects
 * @devinfo: hardcoded device information
 */
static void init_device_info(struct libdevice *device,
			     const struct libdev *devinfo)
{
	/*
	 * Copy the hardcoded Slot/Token flags into the
	 * runtime flags
	 */
	device->token.flags = devinfo->flags_token;
	device->slot.flags = devinfo->flags_slot;

	/*
	 * Set the default Max Session value to infinite value
	 */
	device->token.max_ro_session = CK_EFFECTIVELY_INFINITE;
	device->token.max_rw_session = CK_EFFECTIVELY_INFINITE;

	/*
	 * Set the default memory Total/Free to unavailable value
	 */
	device->token.total_pub_mem = CK_UNAVAILABLE_INFORMATION;
	device->token.free_pub_mem = CK_UNAVAILABLE_INFORMATION;
	device->token.total_priv_mem = CK_UNAVAILABLE_INFORMATION;
	device->token.free_priv_mem = CK_UNAVAILABLE_INFORMATION;
}

CK_RV libdev_get_slotdev(struct libdevice **dev, CK_SLOT_ID slotid)
{
	CK_RV ret = CKR_OK;
	struct libdevice *devices = NULL;

	*dev = NULL;
	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	if (!libdev_slot_valid(slotid))
		return CKR_SLOT_ID_INVALID;

	*dev = &devices[slotid];

	return CKR_OK;
}

CK_RV libdev_get_slotinfo(CK_SLOT_ID slotid, CK_SLOT_INFO_PTR pinfo)
{
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	const struct libdev *devinfo = NULL;
	size_t len = 0;

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

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

	pinfo->flags = dev->slot.flags;

	if (pinfo->flags & CKF_HW_SLOT) {
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
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;
	const struct libdev *devinfo = NULL;
	struct timespec tp = { 0 };
	struct tm *tminfo = NULL;

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret != CKR_OK)
		return ret;

	devinfo = libdev_get_devinfo(slotid);
	if (!devinfo)
		return CKR_SLOT_ID_INVALID;

	memcpy(pinfo->label, dev->token.label, sizeof(pinfo->label));
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

	pinfo->flags = dev->token.flags;
	if (ADD_OVERFLOW(dev->token.max_ro_session, dev->token.max_rw_session,
			 &pinfo->ulMaxSessionCount))
		return CKR_GENERAL_ERROR;

	if (ADD_OVERFLOW(dev->token.ro_session_count,
			 dev->token.rw_session_count, &pinfo->ulSessionCount))
		return CKR_GENERAL_ERROR;

	pinfo->ulMaxRwSessionCount = dev->token.max_rw_session;
	pinfo->ulRwSessionCount = dev->token.rw_session_count;
	pinfo->ulMaxPinLen = dev->token.max_pin_len;
	pinfo->ulMinPinLen = dev->token.min_pin_len;
	pinfo->ulTotalPublicMemory = dev->token.total_pub_mem;
	pinfo->ulFreePublicMemory = dev->token.free_pub_mem;
	pinfo->ulTotalPrivateMemory = dev->token.total_priv_mem;
	pinfo->ulFreePrivateMemory = dev->token.free_priv_mem;

	if (pinfo->flags & CKF_HW_SLOT) {
		pinfo->hardwareVersion = devinfo->version;
		pinfo->firmwareVersion.major = 0;
		pinfo->firmwareVersion.minor = 0;
	} else {
		pinfo->hardwareVersion.major = 0;
		pinfo->hardwareVersion.minor = 0;
		pinfo->firmwareVersion = devinfo->version;
	}

	/* Get the Realtime clock if available */
	if (!clock_gettime(CLOCK_REALTIME, &tp)) {
		tminfo = localtime(&tp.tv_sec);
		if (!tminfo)
			return CKR_FUNCTION_FAILED;

		(void)strftime((char *)pinfo->utcTime, sizeof(pinfo->utcTime),
			       "%Y%m%d%H%M%S", tminfo);
		pinfo->utcTime[14] = '0';
		pinfo->utcTime[15] = '0';
	} else {
		memset(pinfo->utcTime, 0, sizeof(pinfo->utcTime));
	}

	return CKR_OK;
}

CK_RV libdev_get_slots(CK_ULONG_PTR count, CK_SLOT_ID_PTR slotlist)
{
	CK_RV ret = CKR_OK;
	struct libdevice *devices = NULL;
	CK_SLOT_ID_PTR item = slotlist;
	CK_ULONG nb_slots = 0;
	unsigned int nb_devices = 0;
	unsigned int idx = 0;

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

	for (; idx < nb_devices; idx++) {
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
	CK_RV ret = CKR_OK;
	struct libdevice *devices = NULL;
	CK_SLOT_ID_PTR item = slotlist;
	CK_ULONG nb_slots = 0;
	unsigned int nb_devices = 0;
	unsigned int idx = 0;

	ret = libctx_get_initialized();
	if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED)
		return ret;

	devices = libctx_get_devices();
	if (!devices)
		return CKR_GENERAL_ERROR;

	nb_devices = libdev_get_nb_devinfo();

	/* Update the slot presence */
	libdev_set_present(devices);

	for (; idx < nb_devices; idx++) {
		if (devices[idx].slot.flags & CKF_TOKEN_PRESENT) {
			DBG_TRACE("Slot %u is Present", idx);

			if (INC_OVERFLOW(nb_slots, 1))
				return CKR_GENERAL_ERROR;

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
	CK_RV ret = CKR_OK;
	struct libdevice *dev = NULL;

	ret = libdev_get_slotdev(&dev, slotid);
	if (ret)
		return ret;

	if (!(dev->slot.flags & CKF_TOKEN_PRESENT))
		return CKR_TOKEN_NOT_PRESENT;

	/*
	 * If there is a session opened on this token, it can't be
	 * initialized or re-initialized.
	 */
	if (dev->token.ro_session_count + dev->token.rw_session_count)
		return CKR_SESSION_EXISTS;

	/*
	 * If token already initialized, need to:
	 *  - destroyed all associated objects that can be destroyed
	 *  - re-initialized the token
	 */
	ret = clean_token(dev, slotid);
	if (ret != CKR_OK)
		return ret;

	ret = libdev_mechanisms_init(slotid);
	if (ret != CKR_OK)
		return ret;

	memcpy(dev->token.label, label, sizeof(dev->token.label));

	/*
	 * Initialize the Token counter and flags
	 */
	dev->token.ro_session_count = 0;
	dev->token.rw_session_count = 0;
	dev->login_as = NO_LOGIN;

	/*
	 * Initializze the R/W and Read Only Sessions list
	 */
	LIST_INIT(&dev->rw_sessions);
	LIST_INIT(&dev->ro_sessions);

	/*
	 * Initialize the token objects list
	 */
	ret = LLIST_INIT(&dev->objects);
	if (ret == CKR_OK)
		SET_BITS(dev->token.flags, CKF_TOKEN_INITIALIZED);

	return ret;
}

CK_RV libdev_initialize(struct libdevice **devices)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	unsigned int nb_devices = 0;
	unsigned int slotid = 0;
	struct libdevice *dev = NULL;
	const struct libdev *devinfo = NULL;

	if (!devices)
		return ret;

	*devices = NULL;

	nb_devices = libdev_get_nb_devinfo();
	if (!nb_devices)
		goto end;

	dev = calloc(1, nb_devices * sizeof(*dev));
	if (!dev) {
		ret = CKR_HOST_MEMORY;
		goto end;
	}

	*devices = dev;

	for (slotid = 0; slotid < nb_devices; slotid++) {
		devinfo = libdev_get_devinfo(slotid);
		if (!devinfo) {
			ret = CKR_GENERAL_ERROR;
			break;
		}

		init_device_info(&dev[slotid], devinfo);

		/* Create mutexes */
		ret = libmutex_create(&dev[slotid].mutex_session);
		if (ret != CKR_OK)
			break;
	}

end:
	if (ret != CKR_OK && dev) {
		free(dev);
		*devices = NULL;
	}

	return ret;
}

CK_RV libdev_destroy(struct libdevice **devices)
{
	CK_RV ret = CKR_GENERAL_ERROR;
	struct libdevice *dev;
	unsigned int nb_devices;
	unsigned int slotid;

	if (!devices)
		return ret;

	/* Nothing to do, it's ok */
	if (!*devices)
		return CKR_OK;

	dev = *devices;

	nb_devices = libdev_get_nb_devinfo();
	for (slotid = 0; slotid < nb_devices; slotid++, dev++) {
		/* Clean Token */
		ret = clean_token(dev, slotid);
		if (ret != CKR_OK)
			return ret;

		/* Destroy mutexes */
		ret = libmutex_destroy(&dev->mutex_session);
		if (ret != CKR_OK)
			return ret;
	};

	free(*devices);
	*devices = NULL;

	return CKR_OK;
}
