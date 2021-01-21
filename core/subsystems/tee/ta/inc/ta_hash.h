/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020-2021 NXP
 */

#ifndef TA_HASH_H
#define TA_HASH_H

/**
 * hash() - Hash a message.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result hash(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_HASH_H */
