/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef TA_MAC_H
#define TA_MAC_H

/**
 * mac_compute() - Compute the MAC of a message.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result mac_compute(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * mac_verify() - Compute and verify the MAC of a message.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result mac_verify(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_MAC_H */
