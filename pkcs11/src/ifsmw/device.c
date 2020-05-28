// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include "smw_config.h"
#include "smw_status.h"

#include "lib_device.h"
#include "util.h"

#include "local.h"

/**
 * struct ifdev - SMW device definition
 * @dev: Constant information
 */
struct ifdev {
	const struct libdev *dev;
};

const struct ifdev smw_devices[] = { { .dev = &hsm_info },
				     { .dev = &optee_info } };

const struct libdev *libdev_get_devinfo(CK_SLOT_ID slotid)
{
	if (slotid < ARRAY_SIZE(smw_devices))
		return smw_devices[slotid].dev;

	return NULL;
}

unsigned int libdev_get_nb_devinfo(void)
{
	return ARRAY_SIZE(smw_devices);
}

void libdev_set_present(struct libdevice *devices)
{
	const struct libdev *devinfo;
	int status;
	unsigned int idx;
	unsigned int nb_devices = libdev_get_nb_devinfo();

	for (idx = 0; idx < nb_devices; idx++) {
		devinfo = libdev_get_devinfo(idx);
		status = smw_config_subsystem_present(devinfo->name);
		if (status == SMW_STATUS_OK)
			SET_BITS(devices[idx].slot.flags, CKF_TOKEN_PRESENT);
		else
			CLEAR_BITS(devices[idx].slot.flags, CKF_TOKEN_PRESENT);
	}
}
