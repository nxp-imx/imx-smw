// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021 NXP
 */

#include "compiler.h"

#include "smw_status.h"
#include "smw_crypto.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"

__weak int smw_hash(struct smw_hash_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int smw_sign(struct smw_sign_verify_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak int smw_verify(struct smw_sign_verify_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
