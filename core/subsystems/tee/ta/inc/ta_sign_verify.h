/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef TA_SIGN_VERIFY_H
#define TA_SIGN_VERIFY_H

/**
 * sign_verify() - Generate or verify a signature.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 * @cmd_id: CMD_SIGN or CMD_VERIFY
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result sign_verify(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS],
		       uint32_t cmd_id);

#endif /* TA_SIGN_VERIFY_H */
