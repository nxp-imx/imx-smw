/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef TA_HMAC_H
#define TA_HMAC_H

/**
 * hmac() - HMAC a message.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result hmac(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_HMAC_H */
