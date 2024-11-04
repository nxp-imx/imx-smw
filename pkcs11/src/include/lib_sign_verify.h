/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021, 2024 NXP
 */

#ifndef __LIB_SIGN_VERIFY_H__
#define __LIB_SIGN_VERIFY_H__

#include "lib_opctx.h"

#include "types.h"

/**
 * lib_signature_ctx - Signature context
 * @hkey: Operation key handle
 * @hash_mech: Hash mechanism
 * @salt_len: Salt length in bytes
 * @mac_len: MAC length in bytes
 * @current_state: Current cipher operation state
 * @context: Pointer to multi-part operation context
 */
struct lib_signature_ctx {
	CK_OBJECT_HANDLE hkey;
	CK_MECHANISM_TYPE hash_mech;
	CK_ULONG salt_len;
	CK_ULONG mac_len;
	enum op_state current_state;
	void *context;
};

/**
 * lib_signature_params - Signature parameters
 * @op_flag: Operation flag
 * @ctx: Pointer to signature context
 * @pdata: Pointer to data
 * @uldatalen: @pdata length in bytes
 * @psignature: Pointer to signature
 * @ulsignaturelen: @psignature length in bytes
 * @state: Operation state to be performed
 */
struct lib_signature_params {
	CK_FLAGS op_flag;
	struct lib_signature_ctx *ctx;
	CK_BYTE_PTR pdata;
	CK_ULONG uldatalen;
	CK_BYTE_PTR psignature;
	CK_ULONG ulsignaturelen;
	enum op_state state;
};

/**
 * lib_sign_verify_cancel_operation() - Cancel the multi-part sign or verify
 * operation, if active
 * @hsession: Session handle
 * @op_flag: Operation flag
 *
 * Check if any multi-part sign or verify operation is active.
 * If a multi-part operation is active, cancel the operation
 * and remove the operation context.
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session Handle invalid
 * CKR_DEVICE_ERROR	              - Device failure
 * CKR_OK                             - Success
 */
CK_RV lib_sign_verify_cancel_operation(CK_SESSION_HANDLE hsession,
				       CK_FLAGS op_flag);

/**
 * lib_sign_verify_init() - Initialize a Sign or Verify operation
 * @hsession: Session handle
 * @pmechanism: Pointer to operation mechanism
 * @hkey: Key handle
 * @op_flag: Operation flag
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No slot defined or no context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_SLOT_ID_INVALID                - Slot ID is not valid
 * CKR_TOKEN_NOT_PRESENT              - Token is not present
 * CKR_MECHANISM_INVALID              - Mechanism not supported
 * CKR_MECHANISM_PARAM_INVALID        - Machanism parameters invalid
 * CKR_KEY_FUNCTION_NOT_PERMITTED     - Function not permitted with @hkey
 * CKR_OPERATION_ACTIVE               - Operation is already initialized
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_sign_verify_init(CK_SESSION_HANDLE hsession,
			   CK_MECHANISM_PTR pmechanism, CK_OBJECT_HANDLE hkey,
			   CK_FLAGS op_flag);

/**
 * lib_sign_verify_reset() - Reset sign/verify operation
 * @hsession: Session handle
 * @pparameter: Pointer to parameter
 * @ulparameterlen: @pparameter length in bytes
 * @op_flag: Operation flag
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_HOST_MEMORY                    - Allocation error
 * CKR_OK                             - Success
 */
CK_RV lib_sign_verify_reset(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
			    CK_ULONG ulparameterlen, CK_FLAGS op_flag);

/**
 * lib_sign() - Run a sign operation
 * @hsession: Session handle
 * @pparameter: Pointer to parameter
 * @ulparameterlen: @pparameter length in bytes
 * @pdata: Pointer to data
 * @uldatalen: @pdata length in bytes
 * @psignature: Pointer to signature
 * @pulsignaturelen: Pointer to @psignature length in bytes
 * @op_flag: Operation flag
 * @state: Operation state to be performed
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_BUFFER_TOO_SMALL               - Buffer too small
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_DATA_INVALID                   - Data is invalid
 * CKR_DATA_LEN_RANGE                 - Data length is invalid
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_OK                             - Success
 */
CK_RV lib_sign(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
	       CK_ULONG ulparameterlen, CK_BYTE_PTR pdata, CK_ULONG uldatalen,
	       CK_BYTE_PTR psignature, CK_ULONG_PTR pulsignaturelen,
	       CK_FLAGS op_flag, enum op_state state);

/**
 * lib_verify() - Run a verify operation
 * @hsession: Session handle
 * @pparameter: Pointer to parameter
 * @ulparameterlen: @pparameter length in bytes
 * @pdata: Pointer to data
 * @uldatalen: @pdata length in bytes
 * @psignature: Pointer to signature
 * @ulsignaturelen: @psignature length in bytes
 * @op_flag: Operation flag
 * @state: Operation state to be performed
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_BUFFER_TOO_SMALL               - Buffer too small
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_DATA_INVALID                   - Data is invalid
 * CKR_DATA_LEN_RANGE                 - Data length is invalid
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_SIGNATURE_INVALID              - Signature is invalid
 * CKR_SIGNATURE_LEN_RANGE            - Signature length is invalid
 * CKR_OK                             - Success
 */
CK_RV lib_verify(CK_SESSION_HANDLE hsession, CK_VOID_PTR pparameter,
		 CK_ULONG ulparameterlen, CK_BYTE_PTR pdata, CK_ULONG uldatalen,
		 CK_BYTE_PTR psignature, CK_ULONG ulsignaturelen,
		 CK_FLAGS op_flag, enum op_state state);

/**
 * lib_sign_verify_update() - Update a Sign or Verify operation
 * @hsession: Session handle
 * @ppart: Pointer to data
 * @ulpartlen: @ppart length in bytes
 * @op_flag: Operation flag
 *
 * Return:
 * CKR_CRYPTOKI_NOT_INITIALIZED       - Context not initialized
 * CKR_GENERAL_ERROR                  - No context available
 * CKR_SESSION_HANDLE_INVALID         - Session handle invalid
 * CKR_OPERATION_NOT_INITIALIZED      - Operation not initialized
 * CKR_BUFFER_TOO_SMALL               - Buffer too small
 * CKR_ARGUMENTS_BAD                  - Bad arguments
 * CKR_DATA_INVALID                   - Data is invalid
 * CKR_DATA_LEN_RANGE                 - Data length is invalid
 * CKR_FUNCTION_NOT_SUPPORTED         - Operation not supported
 * CKR_DEVICE_MEMORY                  - Device memory error
 * CKR_SIGNATURE_INVALID              - Signature is invalid
 * CKR_SIGNATURE_LEN_RANGE            - Signature length is invalid
 * CKR_OK                             - Success
 */
CK_RV lib_sign_verify_update(CK_SESSION_HANDLE hsession, CK_BYTE_PTR ppart,
			     CK_ULONG ulpartLen, CK_FLAGS op_flag);

#endif /* __LIB_SIGN_VERIFY_H__ */
