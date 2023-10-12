/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef TA_AEAD_H
#define TA_AEAD_H

/**
 * aead_init() - AEAD initialization
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS				- Success
 * TEE_ERROR_BAD_PARAMETERS		- One of the parameters is bad
 * TEE_ERROR_OUT_OF_MEMORY		- Memory allocation failed
 * TEE_ERROR_CORRUPT_OBJECT		- Corrupt key object
 * TEE_ERROR_STORAGE_NOT_AVAILABLE	- Key object not inaccessible
 * TEE_ERROR_NOT_SUPPORTED		- Operation not supported
 */
TEE_Result aead_init(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * aead_update_aad() - AEAD AAD update
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS				- Success
 * TEE_ERROR_BAD_PARAMETERS		- One of the parameters is bad
 */
TEE_Result aead_update_aad(uint32_t param_types,
			   TEE_Param params[TEE_NUM_PARAMS]);

/**
 * aead_update() - AEAD update
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad
 * TEE_ERROR_SHORT_BUFFER	- Output buffer too short
 */
TEE_Result aead_update(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

/**
 * aead_encrypt_final() - AEAD final
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad
 * TEE_ERROR_SHORT_BUFFER	- Output buffer too short
 */
TEE_Result aead_encrypt_final(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS]);

/**
 * aead_decrypt_final() - AEAD final
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is bad
 * TEE_ERROR_SHORT_BUFFER	- Output buffer too short
 * TEE_ERROR_MAC_INVALID	- computed tag does not match the supplied tag
 *
 */
TEE_Result aead_decrypt_final(uint32_t param_types,
			      TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_AEAD_H */
