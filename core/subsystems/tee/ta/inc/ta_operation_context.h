/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef TA_OPERATION_CONTEXT_H
#define TA_OPERATION_CONTEXT_H

/**
 * cancel_operation() - Cancel operation
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid
 */
TEE_Result cancel_operation(uint32_t param_types,
			    TEE_Param params[TEE_NUM_PARAMS]);

/**
 * copy_context() - Copy operation context
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Return:
 * TEE_SUCCESS			- Success
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid
 * TEE_ERROR_OUT_OF_MEMORY	- Memory allocation failed
 * TEE_ERROR_NOT_SUPPORTED	- Operation not supported
 */
TEE_Result copy_context(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* __TA_OPERATION_CONTEXT_H__ */
