/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#include <tee_internal_api.h>

/**
 * check_operation_keys_usage() - Check operation keys usage with given keys
 * @op: Operation handle
 * @key_info: Reference to caller key(s) information
 * @nb_keys: Number of @key_info
 *
 * Return:
 * TEE_SUCCESS              - All given keys are supported by the operation
 * TEE_ERROR_OUT_OF_MEMORY  - Memory allocation failed
 * TEE_BAD_PARAMETERS       - Bad number of key or at least one key's usage
 */
TEE_Result check_operation_keys_usage(TEE_OperationHandle op,
				      TEE_ObjectInfo *key_info,
				      uint32_t nb_keys);

#endif /* __COMMON_H__ */
