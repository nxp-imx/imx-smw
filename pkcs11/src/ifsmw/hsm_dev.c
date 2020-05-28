// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "local.h"

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

FUNC_MECH_INFO(hsm_info_mdigest)
{
	(void)(type);

	DBG_TRACE("Return info of %lu digest mechanism", type);

	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = CKF_DIGEST | CKF_HW;
	return CKR_OK;
}
