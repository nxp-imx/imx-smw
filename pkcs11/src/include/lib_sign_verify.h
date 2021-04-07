/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2021 NXP
 */

#ifndef __LIB_SIGN_VERIFY_H__
#define __LIB_SIGN_VERIFY_H__

#include "types.h"

/**
 * lib_signature_ctx - Signature context
 * @hkey: Operation key handle
 * @hash_mech: Hash mechanism
 * @salt_len: Salt length in bytes
 */
struct lib_signature_ctx {
	CK_OBJECT_HANDLE hkey;
	CK_MECHANISM_TYPE hash_mech;
	CK_ULONG salt_len;
};

/**
 * lib_signature_params - Signature parameters
 * @op_flag: Operation flag
 * @ctx: Pointer to signature context
 * @pdata: Pointer to data
 * @uldatalen: @pdata length in bytes
 * @psignature: Pointer to signature
 * @ulsignaturelen: @psignature length in bytes
 */
struct lib_signature_params {
	CK_FLAGS op_flag;
	struct lib_signature_ctx *ctx;
	CK_BYTE_PTR pdata;
	CK_ULONG uldatalen;
	CK_BYTE_PTR psignature;
	CK_ULONG ulsignaturelen;
};

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
 * lib_sign() - Run a sign operation
 * @hsession: Session handle
 * @pdata: Pointer to data
 * @uldatalen: @pdata length in bytes
 * @psignature: Pointer to signature
 * @pulsignaturelen: Pointer to @psignature length in bytes
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
CK_RV lib_sign(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pdata,
	       CK_ULONG uldatalen, CK_BYTE_PTR psignature,
	       CK_ULONG_PTR pulsignaturelen);

/**
 * lib_verify() - Run a verify operation
 * @hsession: Session handle
 * @pdata: Pointer to data
 * @uldatalen: @pdata length in bytes
 * @psignature: Pointer to signature
 * @ulsignaturelen: @psignature length in bytes
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
CK_RV lib_verify(CK_SESSION_HANDLE hsession, CK_BYTE_PTR pdata,
		 CK_ULONG uldatalen, CK_BYTE_PTR psignature,
		 CK_ULONG ulsignaturelen);

#endif /* __LIB_SIGN_VERIFY_H__ */
