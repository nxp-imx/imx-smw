// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "local.h"

#include "lib_device.h"
#include "pkcs11smw_config.h"

#include "trace.h"

/*
 * Define OPTEE Security Middleware library Secure Subsystem.
 */
const struct libdev optee_info = {
	.name = "OPTEE",
	.description = "OPTEE OS",
	.manufacturer = MANUFACTURER_ID, // or Linaro???
	.model = "",
	.serial = "",
	.version = { 3, 7 },
	.flags_slot = 0,
	.flags_token = 0,
};

FUNC_MECH_INFO(optee_info_mdigest)
{
	(void)(type);

	DBG_TRACE("Return info of %lu digset mechanism", type);

	info->ulMaxKeySize = 0;
	info->ulMinKeySize = 0;
	info->flags = CKF_DIGEST;
	return CKR_OK;
}
