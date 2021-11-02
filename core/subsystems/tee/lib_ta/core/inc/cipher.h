/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021-2022 NXP
 */

#ifndef TA_CIPHER_H
#define TA_CIPHER_H

/**
 * cipher_init() - Cipher initialization
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS				- Success
 * TEE_ERROR_BAD_PARAMETERS		- One of the parameters is bad
 * TEE_ERROR_OUT_OF_MEMORY		- Memory allocation failed
 * TEE_ERROR_CORRUPT_OBJECT		- Corrupt key object
 * TEE_ERROR_CORRUPT_OBJECT_2		- Corrupt key2 object
 * TEE_ERROR_STORAGE_NOT_AVAILABLE	- Key object not inaccessible
 * TEE_ERROR_STORAGE_NOT_AVAILABLE_2	- Key2 object inaccessible
 * TEE_ERROR_NOT_SUPPORTED		- Operation not supported
 * TEE_ERROR_SECURITY			- Key1 and key2 are the same object
 */
TEE_Result cipher_init(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * cipher_update() - Cipher update
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad
 * TEE_ERROR_SHORT_BUFFER	- Output buffer too short
 */
TEE_Result cipher_update(uint32_t param_types,
			 TEE_Param params[TEE_NUM_PARAMS]);

/**
 * cipher_final() - Cipher final
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad
 * TEE_ERROR_SHORT_BUFFER	- Output buffer too short
 */
TEE_Result cipher_final(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_CIPHER_H */
