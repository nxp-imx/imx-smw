/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef TA_ASYMMETRIC_ENCRYPTION_H
#define TA_ASYMMETRIC_ENCRYPTION_H

/**
 * asymm_encrypt_decrypt() - Perform asymmetric encrypt or decrypt operation.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 * @cmd_id: CMD_ASYMM_ENCRYPT or CMD_ASYMM_DECRYPT
 *
 * Return:
 * TEE_SUCCESS			    - Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result asymm_encrypt_decrypt(uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS],
				 uint32_t cmd_id);

#endif /* TA_ASYMMETRIC_ENCRYPTION_H */
