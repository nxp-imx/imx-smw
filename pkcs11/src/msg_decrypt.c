// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2026 NXP
 */

#include "lib_cipher.h"
#include "lib_session.h"

/**
 * C_MessageDecryptInit() - Initialize a message decryption operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Pointer to the decryption mechanism.
 * @hKey: [in] Handle of the decryption key.
 *
 * The CKA_DECRYPT attribute of the decryption key, which indicates whether the
 * key supports decryption, MUST be CK_TRUE.
 *
 * After calling C_MessageDecryptInit(), the application can either call
 * C_DecryptMessage() to decrypt data in a single part; or call
 * C_DecryptMessageBegin() followed by C_DecryptMessageNext() zero or more
 * times, followed by C_MessageDecryptFinal(), to decrypt data in multiple
 * parts. The decryption operation is active until the application uses a call
 * to C_DecryptMessage() or C_MessageDecryptFinal() to actually obtain the final
 * piece of plaintext. To process additional data (in single or multiple parts),
 * the application MUST call C_MessageDecryptInit() again.
 *
 * C_MessageDecryptInit() can be called with @pMechanism set to NULL_PTR to
 * terminate an active decryption operation. If an active operation cannot be
 * cancelled, CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Decryption operation initialized or cancelled if the
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
CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_encrypt_decrypt_init(hSession, pMechanism, hKey,
					CKF_MESSAGE_DECRYPT);
}

/**
 * C_DecryptMessage() - Decrypt a message in a single operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Pointer to mechanism-specific parameters.
 * @ulParameterLen: [in] Length of the parameter data.
 * @pAssociatedData: [in] Pointer to associated data (for AEAD).
 * @ulAssociatedDataLen: [in] Length of associated data.
 * @pCiphertext: [in] Pointer to ciphertext data.
 * @ulCiphertextLen: [in] Length of ciphertext data.
 * @pPlaintext: [out] Pointer to buffer for plaintext output.
 * @pulPlaintextLen: [in/out] Pointer to plaintext length.
 *
 * This function decrypts a complete message in a single call. For AEAD
 * mechanisms, associated data can be provided. The ciphertext and plaintext
 * can be in the same place, i.e., it is OK if @pCiphertext and @pPlaintext
 * point to the same location.
 *
 * To query the required plaintext buffer length, set @pPlaintext to
 * NULL_PTR. The function will then set the required plaintext buffer length in
 * @pulPlaintextLen and return CKR_OK.
 *
 * On operation completion, the @pulPlaintextLen is updated to the correct
 * value when\:
 *
 *  - @pulPlaintextLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulPlaintextLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message decryption operation complete.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulPlaintextLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the decrypted data.
 *  - CKR_DATA_INVALID:
 *      If it's not an Asymmetric Decryption or AEAD decryption, ciphertext
 *      length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      If Asymmetric Decryption or AEAD decryption, ciphertext length is
 *      invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageDecryptInit().
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG_PTR pulPlaintextLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   pAssociatedData, ulAssociatedDataLen,
				   pCiphertext, ulCiphertextLen, pPlaintext,
				   pulPlaintextLen, CKF_MESSAGE_DECRYPT,
				   OP_ONE_SHOT);
}

/**
 * C_DecryptMessageBegin() - Begin a multi-part message decryption operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Pointer to mechanism-specific parameters.
 * @ulParameterLen: [in] Length of the parameter data.
 * @pAssociatedData: [in] Pointer to associated data (for AEAD).
 * @ulAssociatedDataLen: [in] Length of associated data.
 *
 * The message decryption operation MUST have been initialized with
 * C_MessageDecryptInit(). This function begins a multi-part message decryption
 * operation. For AEAD mechanisms, all associated data must be provided in this
 * call before decrypting ciphertext parts with C_DecryptMessageNext().
 *
 * Return:
 *  - CKR_OK:
 *      Success. Multi-part message decryption operation begun.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageDecryptInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_encrypt_decrypt_reset(hSession, pParameter, ulParameterLen,
					 pAssociatedData, ulAssociatedDataLen,
					 CKF_MESSAGE_DECRYPT);
}

/**
 * C_DecryptMessageNext() - Continue a multi-part message decryption operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Pointer to mechanism-specific parameters.
 * @ulParameterLen: [in] Length of the parameter data.
 * @pCiphertext: [in] Pointer to ciphertext data part.
 * @ulCiphertextLen: [in] Length of ciphertext part.
 * @pPlaintext: [out] Pointer to buffer for plaintext output.
 * @pulPlaintextLen: [in/out] Pointer to plaintext part length.
 * @flags: [in] Operation flags (CKF_END_OF_MESSAGE to indicate final part).
 *
 * The message decryption operation MUST have been initialized with
 * C_MessageDecryptInit() and begun with C_DecryptMessageBegin(). This function
 * may be called any number of times in succession. A call to
 * C_DecryptMessageNext() which results in an error other than
 * CKR_BUFFER_TOO_SMALL terminates the current decryption operation.
 *
 * The @flags parameter should include CKF_END_OF_MESSAGE when decrypting the
 * final part of the message.
 *
 * To query the required plaintext buffer length, set @pPlaintext to
 * NULL_PTR. The function will then set the required plaintext buffer length in
 * @pulPlaintextLen and return CKR_OK.
 *
 * On operation completion, the @pulPlaintextLen is updated to the correct
 * value when\:
 *
 *  - @pulPlaintextLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulPlaintextLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message decryption operation updated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - @pulPlaintextLen is NULL_PTR.
 *      - Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the decrypted data part.
 *  - CKR_DATA_INVALID:
 *      If it's not an Asymmetric Decryption or AEAD decryption, ciphertext
 *      length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      If Asymmetric Decryption or AEAD decryption, ciphertext length is
 *      invalid.
 *  - CKR_MECHANISM_PARAM_INVALID
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageDecryptInit().
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertext,
			   CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
			   CK_ULONG_PTR pulPlaintextLen, CK_FLAGS flags)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (flags & CKF_END_OF_MESSAGE)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_encrypt_decrypt(hSession, pParameter, ulParameterLen,
				   NULL_PTR, 0, pCiphertext, ulCiphertextLen,
				   pPlaintext, pulPlaintextLen,
				   CKF_MESSAGE_DECRYPT, state);
}

/**
 * C_MessageDecryptFinal() - Finalize and cancel a message decryption operation.
 * @hSession: [in] Session handle.
 *
 * This function finalizes and cancels an active message decryption operation,
 * releasing any resources associated with the operation context. A call to
 * C_MessageDecryptFinal() always terminates the active message decryption
 * operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message decryption operation finalized and cancelled.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageDecryptInit().
 *  - CKR_GENERAL_ERROR
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	return libsess_cancel_opctx(hSession, CKF_MESSAGE_DECRYPT);
}
