// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2025 NXP
 */

#include "smw/names.h"

#include "dev_config.h"
#include "lib_device.h"
#include "pkcs11smw_config.h"

#include "trace.h"

/*
 * Define Security Middleware library generic device.
 * Use default Secure Subsystem operation defined in
 * the configuration file.
 */
const struct libdev smw_info = {
	.name = SMW_SUBSYSTEM_NAME_NONE,
	.description = "Security Middleware Abstraction",
	.manufacturer = MANUFACTURER_ID,
	.model = "",
	.serial = "",
	.version = { 0, 0 },
	.flags_slot = 0,
	.flags_token =
		CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH,
	.label_token = "smw",
	.profile_id_list = { CKP_BASELINE_PROVIDER },
	.profile_count = 1
};

FUNC_DEV_MECH_INFO(smw_mech_info)
{
	(void)(type);
	(void)(info);

	DBG_TRACE("Complete info of 0x%lx mechanism", type);

	return CKR_OK;
}
