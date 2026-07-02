// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2024, 2026 NXP
 */

#include "lib_sign_verify.h"

/**
 * C_VerifyInit - Initialize verification operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Verification mechanism.
 * @hKey: [in] Key object handle.
 *
 * The CKA_VERIFY attribute of the verification key, which indicates whether
 * the key supports verification, MUST be CK_TRUE.
 *
 * After calling C_VerifyInit(), the application can either call C_Verify() to
 * verify a signature in a single part; or call C_VerifyUpdate() zero or more
 * times, followed by C_VerifyFinal(), to verify a signature in multiple parts.
 * The verification operation is active until the application uses a call to
 * C_Verify() or C_VerifyFinal() to actually perform the final verification.
 * To process additional data (in single or multiple parts), the application
 * MUST call C_VerifyInit() again.
 *
 * C_VerifyInit() can be called with @pMechanism set to NULL_PTR to terminate
 * an active verification operation. If an active operation cannot be cancelled,
 * CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Verification operation initialized or cancelled if the
 *      @pMechanism is NULL_PTR.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_KEY_HANDLE_INVALID:
 *      The @hKey is invalid.
 *  - CKR_MECHANISM_INVALID
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_OPERATION_ACTIVE
 *  - CKR_SLOT_ID_INVALID
 *  - CKR_KEY_FUNCTION_NOT_PERMITTED
 *      Key is not allowed to do the operation.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey, CKF_VERIFY);
}

/**
 * C_Verify - Verify signature in a single part.
 * @hSession: [in] Session handle.
 * @pData: [in] Data buffer.
 * @ulDataLen: [in] Length of data.
 * @pSignature: [in] Signature buffer.
 * @ulSignatureLen: [in] Length of signature.
 *
 * The verification operation MUST have been initialized with C_VerifyInit().
 * A call to C_Verify() always terminates the active verification operation.
 *
 * C_Verify() cannot be used to terminate a multi-part operation, and MUST be
 * called after C_VerifyInit() without intervening C_VerifyUpdate() calls.
 *
 * For most mechanisms, C_Verify() is equivalent to a sequence of
 * C_VerifyUpdate() operations followed by C_VerifyFinal().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Signature is valid.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_DATA_INVALID:
 *      Data length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      Data length is invalid.
 *  - CKR_SIGNATURE_INVALID:
 *      The signature is invalid.
 *  - CKR_SIGNATURE_LEN_RANGE:
 *      The signature length is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_VerifyInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_verify(hSession, NULL_PTR, 0, pData, ulDataLen, pSignature,
			  ulSignatureLen, CKF_VERIFY, OP_ONE_SHOT);
}

/**
 * C_VerifyUpdate - Continue a multi-part verification operation.
 * @hSession: [in] Session handle.
 * @pPart: [in] Data part buffer.
 * @ulPartLen: [in] Length of data part.
 *
 * The verification operation MUST have been initialized with C_VerifyInit().
 * This function may be called any number of times in succession. A call to
 * C_VerifyUpdate() which results in an error terminates the current
 * verification operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Verification operation updated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_DATA_INVALID:
 *      Data length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      Data length is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_VerifyInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign_verify_update(hSession, pPart, ulPartLen, CKF_VERIFY);
}

/**
 * C_VerifyFinal - Finish a multi-part verification operation.
 * @hSession: [in] Session handle.
 * @pSignature: [in] Signature buffer.
 * @ulSignatureLen: [in] Length of signature.
 *
 * The verification operation MUST have been initialized with C_VerifyInit().
 * A call to C_VerifyFinal() always terminates the active verification
 * operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Signature is valid.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_SIGNATURE_INVALID:
 *      The signature is invalid.
 *  - CKR_SIGNATURE_LEN_RANGE:
 *      The signature length is invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_VerifyInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_verify(hSession, NULL_PTR, 0, NULL_PTR, 0, pSignature,
			  ulSignatureLen, CKF_VERIFY, OP_FINAL);
}

/**
 * C_VerifyRecoverInit - Initialize signature recovery verification operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Verification mechanism.
 * @hKey: [in] Key object handle.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_VerifyRecover - Verify signature with data recovery in a single operation.
 * @hSession: [in] Session handle.
 * @pSignature: [in] Signature buffer.
 * @ulSignatureLen: [in] Length of signature.
 * @pData: [out] Recovered data buffer.
 * @pulDataLen: [in/out] Pointer to length of recovered data buffer.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;
	(void)pData;
	(void)pulDataLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
