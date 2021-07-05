// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */
#include "smw_config.h"
#include "smw_status.h"

#include "dev_config.h"
#include "lib_device.h"
#include "util.h"

#include "trace.h"

const struct libdev *libdev_get_devinfo(CK_SLOT_ID slotid)
{
	if (slotid < NB_IFSWM_DEV)
		return smw_devices[slotid].dev;

	return NULL;
}

unsigned int libdev_get_nb_devinfo(void)
{
	return NB_IFSWM_DEV;
}

void libdev_set_present(struct libdevice *devices)
{
	const struct libdev *devinfo;
	enum smw_status_code status;
	unsigned int idx;
	unsigned int nb_devices = libdev_get_nb_devinfo();

	for (idx = 0; idx < nb_devices; idx++) {
		devinfo = libdev_get_devinfo(idx);
		if (devinfo->name)
			status = smw_config_subsystem_present(devinfo->name);
		else
			status = SMW_STATUS_OK;

		DBG_TRACE("SMW subsytem (%u) [%s] present returned %d", idx,
			  devinfo->name ? devinfo->name : "NULL", status);
		if (status == SMW_STATUS_OK)
			SET_BITS(devices[idx].slot.flags, CKF_TOKEN_PRESENT);
		else
			CLEAR_BITS(devices[idx].slot.flags, CKF_TOKEN_PRESENT);
	}
}
