/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2024 NXP
 */

#ifndef TA_KEYMGR_DERIVE_H
#define TA_KEYMGR_DERIVE_H

#include "keymgr.h"

/**
 * derive_key() - Derive a key from base key.
 * @param_types: Parameters types.
 * @params: Shared parameters between Secure and Normal world.
 *
 * Key is derived from base key.
 *
 * Return:
 * TEE_SUCCESS			- Success.
 * TEE_ERROR_BAD_PARAMETERS	- One of the parameters is invalid.
 * Error code from internal functions.
 */
TEE_Result derive_key(uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS]);

#endif /* TA_KEYMGR_DERIVE_H */
