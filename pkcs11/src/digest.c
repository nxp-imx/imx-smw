// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020-2021, 2023-2026 NXP
 */

#include "pkcs11smw.h"

#include "lib_session.h"
#include "lib_device.h"
#include "lib_digest.h"

/**
 * C_DigestInit - Initialize message-digesting operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Digesting mechanism.
 *
 * After calling C_DigestInit(), the application can either call C_Digest() to
 * digest data in a single part; or call C_DigestUpdate() zero or more times,
 * followed by C_DigestFinal(), to digest data in multiple parts. The digesting
 * operation is active until the application uses a call to C_Digest() or
 * C_DigestFinal() to actually obtain the final message digest. To process
 * additional data (in single or multiple parts), the application MUST call
 * C_DigestInit() again.
 *
 * C_DigestInit() can be called with @pMechanism set to NULL_PTR to terminate
 * an active digesting operation. If an active operation cannot be cancelled,
 * CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Digesting operation initialized or cancelled if the
 *      @pMechanism is NULL_PTR.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_MECHANISM_INVALID
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest_init(hSession, pMechanism);
}

/**
 * C_Digest - Digest data in a single part.
 * @hSession: [in] Session handle.
 * @pData: [in] Data buffer to be digested.
 * @ulDataLen: [in] Length of data to be digested.
 * @pDigest: [out] Message digest buffer.
 * @pulDigestLen: [in/out] Pointer to length of message digest buffer.
 *
 * The digesting operation MUST have been initialized with C_DigestInit(). A
 * call to C_Digest() always terminates the active digesting operation unless
 * it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which
 * returns CKR_OK) to determine the length of the buffer needed to hold the
 * message digest.
 *
 * C_Digest() cannot be used to terminate a multi-part operation, and MUST be
 * called after C_DigestInit() without intervening C_DigestUpdate() calls.
 *
 * To query the required message digest buffer length, set @pDigest to
 * NULL_PTR. The function will then set the required message digest buffer
 * length in @pulDigestLen and return CKR_OK.
 *
 * On operation completion, the @pulDigestLen is updated to the correct value
 * when\:
 *
 *  - @pulDigestLen is bigger than expected. In this case, operation succeeds.
 *  - @pulDigestLen is shorter than expected. In this case, operation fails and
 *    returns CKR_BUFFER_TOO_SMALL.
 *
 * C_Digest() is equivalent to a sequence of C_DigestUpdate() operations
 * followed by C_DigestFinal().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Digesting operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulDigestLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the message digest.
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DigestInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest(hSession, pData, ulDataLen, pDigest, pulDigestLen,
			  OP_ONE_SHOT);
}

/**
 * C_DigestUpdate - Continue a multi-part digesting operation.
 * @hSession: [in] Session handle.
 * @pPart: [in] Data part buffer to be digested.
 * @ulPartLen: [in] Length of data part to be digested.
 *
 * The digesting operation MUST have been initialized with C_DigestInit().
 * This function may be called any number of times in succession. A call to
 * C_DigestUpdate() which results in an error terminates the current digesting
 * operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Digesting operation updated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DigestInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest(hSession, pPart, ulPartLen, NULL_PTR, NULL_PTR,
			  OP_UPDATE);
}

/**
 * C_DigestKey - Continue a multi-part digesting operation by digesting a key.
 * @hSession: [in] Session handle.
 * @hKey: [in] Key object handle to be digested.
 *
 * The digesting operation MUST have been initialized with C_DigestInit().
 * This function may be called any number of times in succession, and may be
 * interspersed with C_DigestUpdate() calls. A call to C_DigestKey() which
 * results in an error terminates the current digesting operation.
 *
 * The key value is digested according to the CKA_VALUE attribute of the key
 * object. If the key cannot be digested purely for some reason related to its
 * length, CKR_KEY_SIZE_RANGE is returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Key digested.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_KEY_HANDLE_INVALID:
 *      Key object handle @hKey is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_KEY_INDIGESTIBLE
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DigestInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_digest_key(hSession, hKey);
}

/**
 * C_DigestFinal - Finish a multi-part digesting operation.
 * @hSession: [in] Session handle.
 * @pDigest: [out] Message digest buffer.
 * @pulDigestLen: [in/out] Pointer to length of message digest buffer.
 *
 * The digesting operation MUST have been initialized with C_DigestInit().
 * A call to C_DigestFinal() always terminates the active digesting operation
 * unless it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one
 * which returns CKR_OK) to determine the length of the buffer needed to hold
 * the message digest.
 *
 * To query the required message digest buffer length, set @pDigest to
 * NULL_PTR. The function will then set the required message digest buffer
 * length in @pulDigestLen and return CKR_OK.
 *
 * On operation completion, the @pulDigestLen is updated to the correct value
 * when\:
 *
 *  - @pulDigestLen is bigger than expected. In this case, operation succeeds.
 *  - @pulDigestLen is shorter than expected. In this case, operation fails and
 *    returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Digesting operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulDigestLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the message digest.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DigestInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_digest(hSession, NULL_PTR, 0, pDigest, pulDigestLen,
			  OP_FINAL);
}
