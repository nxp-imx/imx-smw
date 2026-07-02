// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2026 NXP
 */

#include "lib_sign_verify.h"
#include "lib_session.h"

/**
 * C_MessageVerifyInit - Initialize message verification operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Verification mechanism.
 * @hKey: [in] Key object handle.
 *
 * The CKA_VERIFY attribute of the verification key, which indicates whether the
 * key supports verification, MUST be CK_TRUE.
 *
 * After calling C_MessageVerifyInit(), the application can either call
 * C_VerifyMessage() to verify a message in a single part; or call
 * C_VerifyMessageBegin() followed by C_VerifyMessageNext() one or more times,
 * and finally C_MessageVerifyFinal() to verify a message in multiple parts.
 * The message verification operation is active until the application uses a
 * call to C_VerifyMessage() or C_MessageVerifyFinal() to terminate the
 * operation. To process additional messages, the application MUST call
 * C_MessageVerifyInit() again.
 *
 * C_MessageVerifyInit() can be called with @pMechanism set to NULL_PTR to
 * terminate an active message verification operation. If an active operation
 * cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message verification operation initialized or cancelled if the
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
CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey,
				    CKF_MESSAGE_VERIFY);
}

/**
 * C_VerifyMessage - Verify a message in a single part.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Message-specific parameter buffer.
 * @ulParameterLen: [in] Length of message-specific parameter.
 * @pData: [in] Message data to verify buffer.
 * @ulDataLen: [in] Length of message data to verify.
 * @pSignature: [in] Signature buffer.
 * @ulSignatureLen: [in] Length of signature.
 *
 * The message verification operation MUST have been initialized with
 * C_MessageVerifyInit(). A call to C_VerifyMessage() always terminates the
 * active message verification operation unless it returns an error that
 * indicates the operation should continue.
 *
 * C_VerifyMessage() cannot be used to terminate a multi-part operation, and
 * MUST be called after C_MessageVerifyInit() without intervening
 * C_VerifyMessageBegin() or C_VerifyMessageNext() calls.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message verification operation complete and signature is valid.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      - Operation bad state.
 *  - CKR_DATA_INVALID:
 *      Data length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      Data length is invalid.
 *  - CKR_MECHANISM_PARAM_INVALID:
 *      Mechanism parameter is invalid.
 *  - CKR_SIGNATURE_INVALID:
 *      The signature is invalid.
 *  - CKR_SIGNATURE_LEN_RANGE:
 *      The signature length is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageVerifyInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		      CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		      CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_verify(hSession, pParameter, ulParameterLen, pData,
			  ulDataLen, pSignature, ulSignatureLen,
			  CKF_MESSAGE_VERIFY, OP_ONE_SHOT);
}

/**
 * C_VerifyMessageBegin - Begin a multi-part message verification operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Message-specific parameter buffer.
 * @ulParameterLen: [in] Length of message-specific parameter.
 *
 * The message verification operation MUST have been initialized with
 * C_MessageVerifyInit(). This function begins the processing of a new message
 * in a multi-part message verification operation. A call to C_VerifyMessageBegin()
 * which results in an error terminates the current message verification operation.
 *
 * After calling C_VerifyMessageBegin(), the application should call
 * C_VerifyMessageNext() one or more times to process message data parts.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message verification operation reset for new message.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_MECHANISM_PARAM_INVALID:
 *      Mechanism parameter is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageVerifyInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign_verify_reset(hSession, pParameter, ulParameterLen,
				     CKF_MESSAGE_VERIFY);
}

/**
 * C_VerifyMessageNext - Continue a multi-part message verification operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Message-specific parameter buffer.
 * @ulParameterLen: [in] Length of message-specific parameter.
 * @pData: [in] Message data part buffer.
 * @ulDataLen: [in] Length of message data part.
 * @pSignature: [in] Signature buffer (only for final call).
 * @ulSignatureLen: [in] Length of signature (only for final call).
 *
 * The message verification operation MUST have been initialized with
 * C_MessageVerifyInit() and a message started with C_VerifyMessageBegin().
 * This function may be called any number of times in succession to process
 * message data parts.
 *
 * When @pSignature is NULL_PTR, this function processes a message data
 * part without verifying the signature (intermediate call).
 *
 * When @pSignature is not NULL_PTR, this function processes the final
 * message data part and verifies the signature (final call). In this case,
 * the operation for the current message is terminated, but the message
 * verification operation remains active for processing additional messages.
 *
 * A call to C_VerifyMessageNext() which results in an error terminates the
 * current message verification operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message data part processed or signature verified.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_DATA_INVALID:
 *      Data length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      Data length is invalid.
 *  - CKR_MECHANISM_PARAM_INVALID:
 *      Mechanism parameter is invalid.
 *  - CKR_SIGNATURE_INVALID:
 *      The signature is invalid (final call only).
 *  - CKR_SIGNATURE_LEN_RANGE:
 *      The signature length is invalid (final call only).
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageVerifyInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			  CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			  CK_ULONG ulSignatureLen)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (pSignature)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_verify(hSession, pParameter, ulParameterLen, pData,
			  ulDataLen, pSignature, ulSignatureLen,
			  CKF_MESSAGE_VERIFY, state);
}

/**
 * C_MessageVerifyFinal - Finish a multi-part message verification operation.
 * @hSession: [in] Session handle.
 *
 * The message verification operation MUST have been initialized with
 * C_MessageVerifyInit(). A call to C_MessageVerifyFinal() always terminates
 * the active message verification operation.
 *
 * This function is used to terminate the message verification operation without
 * processing any additional messages. It cancels the operation context and
 * releases associated resources.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message verification operation terminated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageVerifyInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	return libsess_cancel_opctx(hSession, CKF_MESSAGE_VERIFY);
}
