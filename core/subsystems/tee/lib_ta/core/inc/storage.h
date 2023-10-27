/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef TA_STORAGE_H
#define TA_STORAGE_H

/**
 * storage_store() - Store object.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 */
TEE_Result storage_store(uint32_t param_types,
			 TEE_Param params[TEE_NUM_PARAMS]);

/**
 * storage_retrieve() - Retrieve object.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 */
TEE_Result storage_retrieve(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS]);

/**
 * storage_delete() - Delete object.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed.
 */
TEE_Result storage_delete(uint32_t param_types,
			  TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_STORAGE_H */
