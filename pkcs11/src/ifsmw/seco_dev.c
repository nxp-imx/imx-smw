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
 * Define SECO Security Middleware library Secure Subsystem.
 */
const struct libdev seco_info = { .name = SMW_SUBSYSTEM_NAME_SECO,
				  .description = "Hardware Secure Module",
				  .manufacturer = MANUFACTURER_ID,
				  .model = "",
				  .serial = "",
				  .version = { 0, 0 },
				  .flags_slot = CKF_HW_SLOT,
				  .flags_token =
					  CKF_TOKEN_INITIALIZED |
					  CKF_PROTECTED_AUTHENTICATION_PATH,
				  .label_token = "smw-seco",
				  .profile_id_list = { CKP_BASELINE_PROVIDER },
				  .profile_count = 1 };

FUNC_DEV_MECH_INFO(seco_mech_info)
{
	(void)(type);

	DBG_TRACE("Complete info of 0x%lx mechanism", type);
	if (info->flags & CKF_DIGEST)
		info->flags |= CKF_HW;

	return CKR_OK;
}
