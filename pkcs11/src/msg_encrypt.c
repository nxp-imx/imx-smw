// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2026 NXP
 */

#include "lib_cipher.h"
#include "lib_session.h"

/**
 * C_MessageEncryptInit() - Initialize a message encryption operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Pointer to the encryption mechanism.
 * @hKey: [in] Handle of the encryption key.
 *
 * The CKA_ENCRYPT attribute of the encryption key, which indicates whether the
 * key supports encryption, MUST be CK_TRUE.
 *
 * After calling C_MessageEncryptInit(), the application can either call
 * C_EncryptMessage() to encrypt data in a single part; or call
 * C_EncryptMessageBegin() followed by C_EncryptMessageNext() zero or more
 * times, followed by C_MessageEncryptFinal(), to encrypt data in multiple
 * parts. The encryption operation is active until the application uses a call
 * to C_EncryptMessage() or C_MessageEncryptFinal() to actually obtain the final
 * piece of ciphertext. To process additional data (in single or multiple parts),
 * the application MUST call C_MessageEncryptInit() again.
 *
 * C_MessageEncryptInit() can be called with @pMechanism set to NULL_PTR to
 * terminate an active encryption operation. If an active operation cannot be
 * cancelled, CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Encryption operation initialized or cancelled if the
 *      @pMechanism is NULL_PTR.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle is invalid.
 *  - CKR_KEY_HANDLE_INVALID:
 *      The @hKey is invalid.
 *  - CKR_MECHANISM_INVALID
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_MESSAGE_ENCRYPT);
}

/**
 * C_EncryptMessage() - Encrypt a message in a single operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Pointer to mechanism-specific parameters.
 * @ulParameterLen: [in] Length of the parameter data.
 * @pAssociatedData: [in] Pointer to associated data (for AEAD).
 * @ulAssociatedDataLen: [in] Length of associated data.
 * @pPlaintext: [in] Pointer to plaintext data.
 * @ulPlaintextLen: [in] Length of plaintext data.
 * @pCiphertext: [out] Pointer to buffer for ciphertext output.
 * @pulCiphertextLen: [in/out] Pointer to ciphertext length.
 *
 * This function encrypts a complete message in a single call. For AEAD
 * mechanisms, associated data can be provided. The plaintext and ciphertext
 * can be in the same place, i.e., it is OK if @pPlaintext and @pCiphertext
 * point to the same location.
 *
 * To query the required ciphertext buffer length, set @pCiphertext to
 * NULL_PTR. The function will then set the required ciphertext buffer length in
 * @pulCiphertextLen and return CKR_OK.
 *
 * On operation completion, the @pulCiphertextLen is updated to the correct
 * value when\:
 *
 *  - @pulCiphertextLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulCiphertextLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message encryption operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulCiphertextLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the encrypted data.
 *  - CKR_DATA_INVALID:
 *      If it's not an Asymmetric Encryption or AEAD encryption, plaintext
 *      length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      If Asymmetric Encryption or AEAD encryption, plaintext length is
 *      invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageEncryptInit().
 *  - CKR_MECHANISM_PA​RAM_INVALID
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   pAssociatedData, ulAssociatedDataLen,
				   pPlaintext, ulPlaintextLen, pCiphertext,
				   pulCiphertextLen, CKF_MESSAGE_ENCRYPT,
				   OP_ONE_SHOT);
}

/**
 * C_EncryptMessageBegin() - Begin a multi-part message encryption operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Pointer to mechanism-specific parameters.
 * @ulParameterLen: [in] Length of the parameter data.
 * @pAssociatedData: [in] Pointer to associated data (for AEAD).
 * @ulAssociatedDataLen: [in] Length of associated data.
 *
 * The message encryption operation MUST have been initialized with
 * C_MessageEncryptInit(). This function begins a multi-part message encryption
 * operation. For AEAD mechanisms, all associated data must be provided in this
 * call before encrypting plaintext parts with C_EncryptMessageNext().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Multi-part message encryption operation begun.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageEncryptInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt_reset(hSession, pParameter, ulParameterLen,
					 pAssociatedData, ulAssociatedDataLen,
					 CKF_MESSAGE_ENCRYPT);
}

/**
 * C_EncryptMessageNext() - Continue a multi-part message encryption operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Pointer to mechanism-specific parameters.
 * @ulParameterLen: [in] Length of the parameter data.
 * @pPlaintextPart: [in] Pointer to plaintext data part.
 * @ulPlaintextPartLen: [in] Length of plaintext part.
 * @pCiphertextPart: [out] Pointer to buffer for ciphertext output.
 * @pulCiphertextPartLen: [in/out] Pointer to ciphertext part length.
 * @flags: [in] Operation flags (CKF_END_OF_MESSAGE to indicate final part).
 *
 * The message encryption operation MUST have been initialized with
 * C_MessageEncryptInit() and begun with C_EncryptMessageBegin(). This function
 * may be called any number of times in succession. A call to
 * C_EncryptMessageNext() which results in an error other than
 * CKR_BUFFER_TOO_SMALL terminates the current encryption operation.
 *
 * The @flags parameter should include CKF_END_OF_MESSAGE when encrypting the
 * final part of the message.
 *
 * To query the required ciphertext buffer length, set @pCiphertextPart to
 * NULL_PTR. The function will then set the required ciphertext buffer length in
 * @pulCiphertextPartLen and return CKR_OK.
 *
 * On operation completion, the @pulCiphertextPartLen is updated to the correct
 * value when\:
 *
 *  - @pulCiphertextPartLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulCiphertextPartLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message encryption operation updated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulCiphertextPartLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the encrypted data part.
 *  - CKR_DATA_INVALID:
 *      If it's not an Asymmetric Encryption or AEAD encryption, plaintext
 *      length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      If Asymmetric Encryption or AEAD encryption, plaintext length is
 *      invalid.
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageEncryptInit().
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG ulPlaintextPartLen,
			   CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (flags & CKF_END_OF_MESSAGE)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   NULL_PTR, 0, pPlaintextPart,
				   ulPlaintextPartLen, pCiphertextPart,
				   pulCiphertextPartLen, CKF_MESSAGE_ENCRYPT,
				   state);
}

/**
 * C_MessageEncryptFinal() - Finalize and cancel a message encryption operation.
 * @hSession: [in] Session handle.
 *
 * This function finalizes and cancels an active message encryption operation,
 * releasing any resources associated with the operation context. A call to
 * C_MessageEncryptFinal() always terminates the active message encryption
 * operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message encryption operation finalized and cancelled.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageEncryptInit().
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	return libsess_cancel_opctx(hSession, CKF_MESSAGE_ENCRYPT);
}
