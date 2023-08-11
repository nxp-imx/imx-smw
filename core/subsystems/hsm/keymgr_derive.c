// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"
#include "keymgr_derive_tls12.h"

__weak int hsm_derive_tls12(struct subsystem_context *hsm_ctx,
			    struct smw_keymgr_derive_key_args *args)
{
	(void)hsm_ctx;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

int hsm_derive_key(struct subsystem_context *hsm_ctx,
		   struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(hsm_ctx && args);

	switch (args->kdf_id) {
	case SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE:
		status = hsm_derive_tls12(hsm_ctx, args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
