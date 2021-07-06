// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021 NXP
 */

#include "smw_status.h"

#include "compiler.h"
#include "debug.h"
#include "operations.h"
#include "subsystems.h"

#include "common.h"
#include "keymgr_derive_tls12.h"

__weak int derive_tls12(struct hdl *hdl,
			struct smw_keymgr_derive_key_args *args)
{
	(void)hdl;
	(void)args;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

int derive_key(struct hdl *hdl, struct smw_keymgr_derive_key_args *args)
{
	int status = SMW_STATUS_OPERATION_NOT_SUPPORTED;

	SMW_DBG_TRACE_FUNCTION_CALL;

	SMW_DBG_ASSERT(args);

	switch (args->kdf_id) {
	case SMW_CONFIG_KDF_TLS12_KEY_EXCHANGE:
		status = derive_tls12(hdl, args);
		break;

	default:
		break;
	}

	SMW_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
