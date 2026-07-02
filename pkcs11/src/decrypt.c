// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023-2024, 2026 NXP
 */

#include "lib_cipher.h"

/**
 * C_DecryptInit - Initialize decryption operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Decryption mechanism.
 * @hKey: [in] Key object handle.
 *
 * The CKA_DECRYPT attribute of the decryption key, which indicates whether the
 * key supports decryption, MUST be CK_TRUE.
 *
 * After calling C_DecryptInit(), the application can either call C_Decrypt() to
 * decrypt data in a single part; or call C_DecryptUpdate() zero or more times,
 * followed by C_DecryptFinal(), to decrypt data in multiple parts.  The
 * decryption operation is active until the application uses a call to
 * C_Decrypt() or C_DecryptFinal() to actually obtain the final piece of
 * plaintext.  To process additional data (in single or multiple parts), the
 * application MUST call C_DecryptInit() again.
 *
 * C_DecryptInit() can be called with @pMechanism set to NULL_PTR to terminate
 * an active decryption operation.  If an active operation cannot be cancelled,
 * CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Decryption operation initialized or cancelled if the
 *      @pMechanism is NULL_PTR.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_KEY_HANDLE_INVALID:
 *      Key object handle @hKey is invalid.
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_DECRYPT);
}

/**
 * C_Decrypt - Decrypt data in a single part.
 * @hSession: [in] Session handle.
 * @pEncryptedData: [in] Encrypted data buffer.
 * @ulEncryptedDataLen: [in] Length of encrypted data.
 * @pData: [out] Decrypted data buffer.
 * @pulDataLen: [in/out] Pointer to length of decrypted data buffer.
 *
 * The decryption operation MUST have been initialized with C_DecryptInit(). A
 * call to C_Decrypt() always terminates the active decryption operation unless
 * it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which
 * returns CKR_OK) to determine the length of the buffer needed to hold the
 * plaintext.
 *
 * C_Decrypt() cannot be used to terminate a multi-part operation, and MUST be
 * called after C_DecryptInit() without intervening C_DecryptUpdate() calls.
 *
 * To query the required plaintext buffer length, set @pData to NULL_PTR. The
 * function will then set the required plaintext buffer length in @pulDataLen
 * and return CKR_OK.
 *
 * On operation completion, the @pulDataLen is updated to the correct value
 * when\:
 *
 *  - @pulDataLen is bigger than expected. In this case, operation succeeds.
 *  - @pulDataLen is shorter than expected. In this case, operation fails and
 *    returns CKR_BUFFER_TOO_SMALL.
 *
 * For most mechanisms, C_Decrypt() is equivalent to a sequence of
 * C_DecryptUpdate() operations followed by C_DecryptFinal().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Decryption operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulDataLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the decrypted data.
 *  - CKR_ENCRYPTED_DATA_INVALID:
 *      If it's not an Asymmetric Encryption or AEAD decryption, ciphertext
 *      length is invalid.
 *  - CKR_ENCRYPTED_DATA_LEN_RANGE:
 *      If Asymmetric Encryption or AEAD decryption, ciphertext length is
 *      invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DecryptInit().
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL_PTR, 0, NULL_PTR, 0,
				   pEncryptedData, ulEncryptedDataLen, pData,
				   pulDataLen, CKF_DECRYPT, OP_ONE_SHOT);
}

/**
 * C_DecryptUpdate - Continue a multi-part decryption operation.
 * @hSession: [in] Session handle.
 * @pEncryptedPart: [in] Encrypted data part buffer.
 * @ulEncryptedPartLen: [in] Length of encrypted data part.
 * @pPart: [out] Decrypted data part buffer.
 * @pulPartLen: [in/out] Pointer to length of decrypted data part buffer.
 *
 * The decryption operation MUST have been initialized with C_DecryptInit().
 * This function may be called any number of times in succession. A call to
 * C_DecryptUpdate() which results in an error other than CKR_BUFFER_TOO_SMALL
 * terminates the current decryption operation.
 *
 * To query the required plaintext buffer length, set @pData to NULL_PTR. The
 * function will then set the required plaintext buffer length in @pulDataLen
 * and return CKR_OK.
 *
 * On operation completion, the @pulDataLen is updated to the correct value
 * when\:
 *
 *  - @pulDataLen is bigger than expected. In this case, operation succeeds.
 *  - @pulDataLen is shorter than expected. In this case, operation fails and
 *    returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Decryption operation updated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulPartLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the decrypted data part.
 *  - CKR_ENCRYPTED_DATA_INVALID:
 *      If it's not an Asymmetric Encryption or AEAD decryption, cipher text
 *      length is invalid.
 *  - CKR_ENCRYPTED_DATA_LEN_RANGE:
 *      If Asymmetric Encryption or AEAD decryption, cipher text length is
 *      invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DecryptInit().
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL_PTR, 0, NULL_PTR, 0,
				   pEncryptedPart, ulEncryptedPartLen, pPart,
				   pulPartLen, CKF_DECRYPT, OP_UPDATE);
}

/**
 * C_DecryptFinal - Finish a multi-part decryption operation.
 * @hSession: [in] Session handle.
 * @pLastPart: [out] Last decrypted data part buffer.
 * @pulLastPartLen: [in/out] Pointer to length of last decrypted data part.
 *
 * The decryption operation MUST have been initialized with C_DecryptInit().
 * A call to C_DecryptFinal() always terminates the active decryption operation
 * unless it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one
 * which returns CKR_OK) to determine the length of the buffer needed to hold
 * the plaintext.
 *
 * To query the required plaintext buffer length, set @pLastPart to NULL_PTR.
 * The function will then set the required plaintext buffer length in
 * @pulLastPartLen and return CKR_OK.
 *
 * On operation completion, the @pulLastPartLen is updated to the correct value
 * when\:
 *
 *  - @pulLastPartLen is bigger than expected. In this case, operation succeeds.
 *  - @pulLastPartLen is shorter than expected. In this case, operation fails
 *    and returns CKR_BUFFER_TOO_SMALL.
 *
 *
 * Return:
 *  - CKR_OK:
 *      Success. Decryption operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulLastPartLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the last decrypted data part.
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_DecryptInit().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR,
				   0, pLastPart, pulLastPartLen, CKF_DECRYPT,
				   OP_FINAL);
}
