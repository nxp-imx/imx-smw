/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef TA_RNG_H
#define TA_RNG_H

/**
 * rng() - Generate random number.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 */
TEE_Result rng(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_RNG_H */
