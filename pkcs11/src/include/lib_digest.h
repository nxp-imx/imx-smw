/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2024-2025 NXP
 */

#ifndef __LIB_DIGEST_H__
#define __LIB_DIGEST_H__

#include "lib_opctx.h"

/**
 * lib_digest_ctx - Digest context
 * @current_state: Current digest operation state
 * @context: Pointer to multi-part operation context
 */
struct lib_digest_ctx {
	enum op_state current_state;
	void *context;
};

struct libdig_params {
	struct lib_digest_ctx *ctx;
	CK_BYTE_PTR pdata;
	CK_ULONG data_len;
	CK_BYTE_PTR pdigest;
	CK_ULONG digest_len;
	enum op_state state;
};

/**
 * lib_digest_init() - Initialize digest operation
 * @hsession: Session handle
 * @pmechanism: Pointer to operation mechanism
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined or no context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_SLOT_ID_INVALID                - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT              - Token is not present
 * CKR_MECHANISM_INVALID              - Mechanism not supported
 * CKR_OPERATION_ACTIVE               - Operation is already initialized
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_digest_init(CK_SESSION_HANDLE hsession, CK_MECHANISM_PTR pmechanism);

/**
 * lib_digest() - Perform digest operation
 * @hsession: Session handle
 * @pdata: Pointer to input data buffer
 * @data_len: Pointer to input data buffer length in bytes
 * @pdigest: Pointer to digest buffer
 * @pdigest_len: Pointer to digest buffer length in bytes
 * @state: Operation state to be performed
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_BUFFER_TOO_SMALL               - Buffer too small
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_digest(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pdata,
		 CK_ULONG data_len, CK_BYTE_PTR pdigest,
		 CK_ULONG_PTR pdigest_len, enum op_state state);

/**
 * lib_digest_key() - Perform digesting the value of a secret key.
 * @hsession: Session handle
 * @hkey: Key handle
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_KEY_INDIGESTIBLE               - Key is indigestible
 * CKR_OK                             - Success
 */
CK_RV lib_digest_key(CK_SESSION_HANDLE hsession, CK_OBJECT_HANDLE hkey);

/**
 * lib_digest_copy_operation() - Create a copy of the multi-part digest
 *                               operation, if active
 * @src: The source context
 * @dst: The destination context
 *
 * Check if any multi-part digest operation is active.
 * If a multi-part operation is active, copy the operation
 * context into @dst.
 *
 * Return:
 * CKR_STATE_UNSAVEABLE               - State cannot be saved
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_FUNCTION_FAILED                - Operation failed
 * CKR_OBJECT_HANDLE_INVALID          - Object not found
 * CKR_DEVICE_ERROR                   - Device failure
 * CKR_OK                             - Success
 */
CK_RV lib_digest_copy_operation(void *src, void **dst);

#endif /* __LIB_DIGEST_H__ */
