// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022, 2024-2026 NXP
 */
#include "smw_status.h"

#include "compiler.h"
#include "debug.h"

#include "common.h"

__weak int derive_hkdf(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int derive_tls12(struct hdl *hdl,
			struct smw_keymgr_derive_key_args *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int derive_tls12_op(struct hdl *hdl,
			   struct smw_keymgr_derive_key_args *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int derive_tls13(struct subsystem_context *ele_ctx,
			struct smw_keymgr_derive_key_args *args)
{
	(void)ele_ctx;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

int ele_derive_key(struct subsystem_context *ele_ctx,
		   struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(args);

	switch (args->kdf_id) {
	case SMW_CONFIG_KDF_ID_TLS12_KEY_EXCHANGE:
		status = derive_tls12(&ele_ctx->hdl, args);
		break;

	case SMW_CONFIG_KDF_ID_TLS12_OP_KEY_EXCHANGE:
		status = derive_tls12_op(&ele_ctx->hdl, args);
		break;

	case SMW_CONFIG_KDF_ID_TLS13_KEY_EXCHANGE:
		status = derive_tls13(ele_ctx, args);
		break;

	case SMW_CONFIG_KDF_ID_HKDF:
	case SMW_CONFIG_KDF_ID_HKDF_EXTRACT:
	case SMW_CONFIG_KDF_ID_HKDF_EXPAND:
		status = derive_hkdf(&ele_ctx->hdl, args);
		break;

	case SMW_CONFIG_KDF_ID_OEM_MASTER_KEY:
		status = derive_oem_mk(ele_ctx, args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);

	// coverity[missing_unlock]
	return status;
}
