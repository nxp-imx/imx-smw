// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */
#include "dev_config.h"
#include "lib_device.h"
#include "pkcs11smw_config.h"

#include "trace.h"

/*
 * Define HSM Security Middleware library Secure Subsystem.
 */
const struct libdev hsm_info = {
	.name = "HSM",
	.description = "Hardware Secure Module",
	.manufacturer = MANUFACTURER_ID,
	.model = "",
	.serial = "",
	.version = { 0, 0 },
	.flags_slot = CKF_HW_SLOT,
	.flags_token = 0,
};

FUNC_DEV_MECH_INFO(hsm_mech_info)
{
	(void)(type);

	DBG_TRACE("Complete info of 0x%lx mechanism", type);
	if (info->flags & CKF_DIGEST)
		info->flags |= CKF_HW;

	return CKR_OK;
}
