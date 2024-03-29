// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023 NXP
 */

#include "compiler.h"

#include "smw_status.h"
#include "smw_crypto.h"

#include "global.h"
#include "debug.h"
#include "utils.h"

__weak enum smw_status_code smw_hash(struct smw_hash_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_sign(struct smw_sign_verify_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_verify(struct smw_sign_verify_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_hmac(struct smw_hmac_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_rng(struct smw_rng_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_cipher(struct smw_cipher_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_cipher_init(struct smw_cipher_init_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_cipher_update(struct smw_cipher_data_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_cipher_final(struct smw_cipher_data_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_cancel_operation(struct smw_op_context *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_copy_context(struct smw_op_context *dst,
					     struct smw_op_context *src)
{
	(void)dst;
	(void)src;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_mac(struct smw_mac_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_mac_verify(struct smw_mac_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_aead(struct smw_aead_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_aead_init(struct smw_aead_init_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_aead_update_add(struct smw_aead_aad_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_aead_update(struct smw_aead_data_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}

__weak enum smw_status_code smw_aead_final(struct smw_aead_final_args *args)
{
	(void)args;

	SMW_DBG_TRACE_FUNCTION_CALL;

	return SMW_STATUS_OPERATION_NOT_SUPPORTED;
}
