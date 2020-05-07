// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "smw_status.h"
#include "smw_crypto.h"

#include "smw_osal.h"
#include "global.h"
#include "debug.h"
#include "utils.h"

__attribute__((weak)) int smw_hash(struct smw_hash_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_sign(struct smw_sign_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__attribute__((weak)) int smw_verify(struct smw_verify_args *args)
{
	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
