/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2023 NXP
 */

#ifndef __KEYMGR_DERIVE_TLS12_H__
#define __KEYMGR_DERIVE_TLS12_H__

/**
 * hsm_derive_tls12() - TLS 1.2 key derivation
 * @hsm_ctx: Pointer to the HSM subsystem context structure.
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
int hsm_derive_tls12(struct subsystem_context *hsm_ctx,
		     struct smw_keymgr_derive_key_args *args);

#endif /* __KEYMGR_DERIVE_TLS12_H__ */
