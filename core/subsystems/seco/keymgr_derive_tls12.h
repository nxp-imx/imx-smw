/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023-2025 NXP
 */

#ifndef __KEYMGR_DERIVE_TLS12_H__
#define __KEYMGR_DERIVE_TLS12_H__

#include "keymgr_derive.h"

#include "common.h"

/**
 * seco_derive_tls12() - TLS 1.2 key derivation
 * @seco_ctx: Pointer to the SECO subsystem context structure.
 * @args: Pointer to SMW key derivation arguments.
 *
 * Return:
 * SMW_STATUS_OK			- Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED	- Operation not supported
 * SMW_STATUS_OUTPUT_TOO_SHORT		- Output buffer length too short
 * SMW_STATUS_INVALID_PARAM		- One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE		- Memory allocation failure
 * SMW_STATUS_UNKNOWN_ID		- Unknown key identifier
 * SMW_STATUS_SUBSYSTEM_FAILURE		- Subsystem failure
 */
int seco_derive_tls12(struct subsystem_context *seco_ctx,
		      struct smw_keymgr_derive_key_args *args);

/**
 * seco_derive_tls12_op() - TLS 1.2 "Operation-based" key derivation
 * @seco_ctx: Pointer to the SECO subsystem context structure.
 * @args: Pointer to SMW key derivation arguments.
 *
 * Return:
 * SMW_STATUS_OK                      - Success
 * SMW_STATUS_OPERATION_NOT_SUPPORTED - Operation not supported
 * SMW_STATUS_OUTPUT_TOO_SHORT        - Output buffer length too short
 * SMW_STATUS_INVALID_PARAM           - One of the parameters is invalid
 * SMW_STATUS_ALLOC_FAILURE           - Memory allocation failure
 * SMW_STATUS_UNKNOWN_ID              - Unknown key identifier
 * SMW_STATUS_SUBSYSTEM_FAILURE       - Subsystem failure
 */
int seco_derive_tls12_op(struct subsystem_context *seco_ctx,
			 struct smw_keymgr_derive_key_args *args);

/**
 * seco_free_tls12_context() - Free the ELE signature context
 * @ctx: Signature context
 *
 * Return:
 * None.
 */
void seco_free_tls12_context(struct smw_op_context *ctx);

#endif /* __KEYMGR_DERIVE_TLS12_H__ */
