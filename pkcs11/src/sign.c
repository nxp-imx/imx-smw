// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2024, 2026 NXP
 */

#include "lib_sign_verify.h"

/**
 * C_SignInit - Initialize signature operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Signature mechanism.
 * @hKey: [in] Key object handle.
 *
 * The CKA_SIGN attribute of the signature key, which indicates whether the
 * key supports signing, MUST be CK_TRUE.
 *
 * After calling C_SignInit(), the application can either call C_Sign() to
 * sign data in a single part; or call C_SignUpdate() zero or more times,
 * followed by C_SignFinal(), to sign data in multiple parts. The
 * signature operation is active until the application uses a call to
 * C_Sign() or C_SignFinal() to actually obtain the final signature.
 * To process additional data (in single or multiple parts), the
 * application MUST call C_SignInit() again.
 *
 * C_SignInit() can be called with @pMechanism set to NULL_PTR to terminate
 * an active signature operation. If an active operation cannot be cancelled,
 * CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Signature operation initialized or cancelled if the
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
CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey, CKF_SIGN);
}

/**
 * C_Sign - Sign data in a single part.
 * @hSession: [in] Session handle.
 * @pData: [in] Data to sign buffer.
 * @ulDataLen: [in] Length of data to sign.
 * @pSignature: [out] Signature buffer.
 * @pulSignatureLen: [in/out] Pointer to length of signature buffer.
 *
 * The signature operation MUST have been initialized with C_SignInit(). A
 * call to C_Sign() always terminates the active signature operation unless
 * it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which
 * returns CKR_OK) to determine the length of the buffer needed to hold the
 * signature.
 *
 * C_Sign() cannot be used to terminate a multi-part operation, and MUST be
 * called after C_SignInit() without intervening C_SignUpdate() calls.
 *
 * To query the required signature buffer length, set @pSignature to
 * NULL_PTR. The function will then set the required signature buffer length in
 * @pulSignatureLen and return CKR_OK.
 *
 * On operation completion, the @pulSignatureLen is updated to the correct
 * value when\:
 *
 *  - @pulSignatureLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulSignatureLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * For most mechanisms, C_Sign() is equivalent to a sequence of
 * C_SignUpdate() operations followed by C_SignFinal().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Signature operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulSignatureLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the signature.
 *  - CKR_DATA_INVALID:
 *      Data length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      Data length is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_SignInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign(hSession, NULL_PTR, 0, pData, ulDataLen, pSignature,
			pulSignatureLen, CKF_SIGN, OP_ONE_SHOT);
}

/**
 * C_SignUpdate - Continue a multi-part signature operation.
 * @hSession: [in] Session handle.
 * @pPart: [in] Data part buffer.
 * @ulPartLen: [in] Length of data part.
 *
 * The signature operation MUST have been initialized with C_SignInit().
 * This function may be called any number of times in succession. A call to
 * C_SignUpdate() which results in an error terminates the current signature
 * operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Signature operation updated.
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
 *      The operation must be initialized with C_SignInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign_verify_update(hSession, pPart, ulPartLen, CKF_SIGN);
}

/**
 * C_SignFinal - Finish a multi-part signature operation.
 * @hSession: [in] Session handle.
 * @pSignature: [out] Signature buffer.
 * @pulSignatureLen: [in/out] Pointer to length of signature buffer.
 *
 * The signature operation MUST have been initialized with C_SignInit().
 * A call to C_SignFinal() always terminates the active signature operation
 * unless it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one
 * which returns CKR_OK) to determine the length of the buffer needed to hold
 * the signature.
 *
 * To query the required signature buffer length, set @pSignature to
 * NULL_PTR. The function will then set the required signature buffer length in
 * @pulSignatureLen and return CKR_OK.
 *
 * On operation completion, the @pulSignatureLen is updated to the
 * correct value when\:
 *
 *  - @pulSignatureLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulSignatureLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Signature operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulSignatureLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the signature.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_SignInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign(hSession, NULL_PTR, 0, NULL_PTR, 0, pSignature,
			pulSignatureLen, CKF_SIGN, OP_FINAL);
}

/**
 * C_SignRecoverInit - Initialize signature recovery operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Signature mechanism.
 * @hKey: [in] Key object handle.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_SignRecover - Sign data in a single operation with data recovery.
 * @hSession: [in] Session handle.
 * @pData: [in] Data to sign buffer.
 * @ulDataLen: [in] Length of data to sign.
 * @pSignature: [out] Signature buffer.
 * @pulSignatureLen: [in/out] Pointer to length of signature buffer.
 *
 * .. note::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function not supported.
 */
CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
