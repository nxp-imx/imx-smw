// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2022 NXP
 */

#include "dev_config.h"
#include "lib_device.h"
#include "pkcs11smw_config.h"

#include "trace.h"

/*
 * Define OPTEE Security Middleware library Secure Subsystem.
 */
const struct libdev optee_info = {
	.name = "TEE",
	.description = "OPTEE OS",
	.manufacturer = MANUFACTURER_ID, // or Linaro???
	.model = "",
	.serial = "",
	.version = { 3, 7 },
	.flags_slot = 0,
	.flags_token = 0,
};

FUNC_DEV_MECH_INFO(optee_mech_info)
{
	(void)(type);
	(void)(info);

	DBG_TRACE("Complete info of 0x%lx mechanism", type);

	return CKR_OK;
}
