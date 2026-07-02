// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2023-2024, 2026 NXP
 */

#include "lib_cipher.h"

/**
 * C_EncryptInit - Initialize encryption operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Encryption mechanism.
 * @hKey: [in] Key object handle.
 *
 * The CKA_ENCRYPT attribute of the encryption key, which indicates whether the
 * key supports encryption, MUST be CK_TRUE.
 *
 * After calling C_EncryptInit(), the application can either call C_Encrypt() to
 * encrypt data in a single part; or call C_EncryptUpdate() zero or more times,
 * followed by C_EncryptFinal(), to encrypt data in multiple parts. The
 * encryption operation is active until the application uses a call to
 * C_Encrypt() or C_EncryptFinal() to actually obtain the final piece of
 * ciphertext. To process additional data (in single or multiple parts), the
 * application MUST call C_EncryptInit() again.
 *
 * C_EncryptInit() can be called with @pMechanism set to NULL_PTR to terminate
 * an active encryption operation. If an active operation cannot be cancelled,
 * CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Encryption operation initialized or cancelled if the
 *      @pMechanism is NULL_PTR.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_KEY_HANDLE_INVALID:
 *      Key object handle @hKey is invalid.
 *  - CKR_MECHANISM_INVALID
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_OPERATION_ACTIVE
 *  - CKR_SLOT_ID_INVALID
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_ENCRYPT);
}

/**
 * C_Encrypt - Encrypt data in a single part.
 * @hSession: [in] Session handle.
 * @pData: [in] Plaintext data buffer.
 * @ulDataLen: [in] Length of plaintext data.
 * @pEncryptedData: [out] Encrypted data buffer.
 * @pulEncryptedDataLen: [in/out] Pointer to length of encrypted data buffer.
 *
 * The encryption operation MUST have been initialized with C_EncryptInit(). A
 * call to C_Encrypt() always terminates the active encryption operation unless
 * it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which
 * returns CKR_OK) to determine the length of the buffer needed to hold the
 * ciphertext.
 *
 * C_Encrypt() cannot be used to terminate a multi-part operation, and MUST be
 * called after C_EncryptInit() without intervening C_EncryptUpdate() calls.
 *
 * To query the required ciphertext buffer length, set @pEncryptedData to
 * NULL_PTR. The function will then set the required ciphertext buffer length in
 * @pulEncryptedDataLen and return CKR_OK.
 *
 * On operation completion, the @pulEncryptedDataLen is updated to the correct
 * value when\:
 *
 *  - @pulEncryptedDataLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulEncryptedDataLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * For most mechanisms, C_Encrypt() is equivalent to a sequence of
 * C_EncryptUpdate() operations followed by C_EncryptFinal().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Encryption operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulEncryptedDataLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the encrypted data.
 *  - CKR_DATA_INVALID:
 *      If it's not an Asymmetric Encryption or AEAD encryption, plaintext
 *      length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      If Asymmetric Encryption or AEAD encryption, plaintext length is
 *      invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_EncryptInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL_PTR, 0, NULL_PTR, 0, pData,
				   ulDataLen, pEncryptedData,
				   pulEncryptedDataLen, CKF_ENCRYPT,
				   OP_ONE_SHOT);
}

/**
 * C_EncryptUpdate - Continue a multi-part encryption operation.
 * @hSession: [in] Session handle.
 * @pPart: [in] Plaintext data part buffer.
 * @ulPartLen: [in] Length of plaintext data part.
 * @pEncryptedPart: [out] Encrypted data part buffer.
 * @pulEncryptedPartLen: [in/out] Pointer to length of encrypted data part
 *                                buffer.
 *
 * The encryption operation MUST have been initialized with C_EncryptInit().
 * This function may be called any number of times in succession. A call to
 * C_EncryptUpdate() which results in an error other than CKR_BUFFER_TOO_SMALL
 * terminates the current encryption operation.
 *
 * To query the required ciphertext buffer length, set @pEncryptedPart to
 * NULL_PTR. The function will then set the required ciphertext buffer length in
 * @pulEncryptedPartLen and return CKR_OK.
 *
 * On operation completion, the @pulEncryptedPartLen is updated to the correct
 * value when\:
 *
 *  - @pulEncryptedPartLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulEncryptedPartLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Encryption operation updated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulEncryptedPartLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the encrypted data part.
 *  - CKR_DATA_INVALID:
 *      If it's not an Asymmetric Encryption or AEAD encryption, plaintext
 *      length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      If Asymmetric Encryption or AEAD encryption, plaintext length is
 *      invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_EncryptInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL_PTR, 0, NULL_PTR, 0, pPart,
				   ulPartLen, pEncryptedPart,
				   pulEncryptedPartLen, CKF_ENCRYPT, OP_UPDATE);
}

/**
 * C_EncryptFinal - Finish a multi-part encryption operation.
 * @hSession: [in] Session handle.
 * @pLastEncryptedPart: [out] Last encrypted data part buffer.
 * @pulLastEncryptedPartLen: [in/out] Pointer to length of last encrypted data
 *                                    part.
 *
 * The encryption operation MUST have been initialized with C_EncryptInit().
 * A call to C_EncryptFinal() always terminates the active encryption operation
 * unless it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one
 * which returns CKR_OK) to determine the length of the buffer needed to hold
 * the ciphertext.
 *
 * To query the required ciphertext buffer length, set @pLastEncryptedPart to
 * NULL_PTR. The function will then set the required ciphertext buffer length in
 * @pulLastEncryptedPartLen and return CKR_OK.
 *
 * On operation completion, the @pulLastEncryptedPartLen is updated to the
 * correct value when\:
 *
 *  - @pulLastEncryptedPartLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulLastEncryptedPartLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Encryption operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulLastEncryptedPartLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the last encrypted data part.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_EncryptInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR,
				   0, pLastEncryptedPart,
				   pulLastEncryptedPartLen, CKF_ENCRYPT,
				   OP_FINAL);
}
