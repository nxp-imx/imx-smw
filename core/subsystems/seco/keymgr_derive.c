// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023-2025 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"
#include "keymgr_derive_tls12.h"

__weak int seco_derive_tls12(struct subsystem_context *seco_ctx,
			     struct smw_keymgr_derive_key_args *args)
{
	(void)seco_ctx;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int seco_derive_tls12_op(struct subsystem_context *seco_ctx,
				struct smw_keymgr_derive_key_args *args)
{
	(void)seco_ctx;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

int seco_derive_key(struct subsystem_context *seco_ctx,
		    struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(seco_ctx && args);

	switch (args->kdf_id) {
	case SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE:
		status = seco_derive_tls12(seco_ctx, args);
		break;

	case SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE:
		status = seco_derive_tls12_op(seco_ctx, args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
