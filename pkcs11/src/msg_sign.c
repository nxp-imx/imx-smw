// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024-2026 NXP
 */

#include "lib_sign_verify.h"
#include "lib_session.h"

/**
 * C_MessageSignInit - Initialize message signature operation.
 * @hSession: [in] Session handle.
 * @pMechanism: [in] Signature mechanism.
 * @hKey: [in] Key object handle.
 *
 * The CKA_SIGN attribute of the signature key, which indicates whether the
 * key supports signing, MUST be CK_TRUE.
 *
 * After calling C_MessageSignInit(), the application can either call
 * C_SignMessage() to sign a message in a single part; or call
 * C_SignMessageBegin() followed by C_SignMessageNext() one or more times,
 * and finally C_MessageSignFinal() to sign a message in multiple parts.
 * The message signature operation is active until the application uses a
 * call to C_SignMessage() or C_MessageSignFinal() to terminate the operation.
 * To process additional messages, the application MUST call
 * C_MessageSignInit() again.
 *
 * C_MessageSignInit() can be called with @pMechanism set to NULL_PTR to
 * terminate an active message signature operation. If an active operation
 * cannot be cancelled, CKR_OPERATION_CANCEL_FAILED must be returned.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message signature operation initialized or cancelled if the
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
CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!hKey)
		return CKR_KEY_HANDLE_INVALID;

	return lib_sign_verify_init(hSession, pMechanism, hKey,
				    CKF_MESSAGE_SIGN);
}

/**
 * C_SignMessage - Sign a message in a single part.
 * @hSession: [in] Session handle.
 * @pParameter: [in/out] Message-specific parameter buffer.
 * @ulParameterLen: [in] Length of message-specific parameter.
 * @pData: [in] Message data to sign buffer.
 * @ulDataLen: [in] Length of message data to sign.
 * @pSignature: [out] Signature buffer.
 * @pulSignatureLen: [in/out] Pointer to length of signature buffer.
 *
 * The message signature operation MUST have been initialized with
 * C_MessageSignInit(). A call to C_SignMessage() always terminates the
 * active message signature operation unless it returns CKR_BUFFER_TOO_SMALL
 * or is a successful call (i.e., one which returns CKR_OK) to determine the
 * length of the buffer needed to hold the signature.
 *
 * C_SignMessage() cannot be used to terminate a multi-part operation, and
 * MUST be called after C_MessageSignInit() without intervening
 * C_SignMessageBegin() or C_SignMessageNext() calls.
 *
 * To query the required signature buffer length, set @pSignature to
 * NULL_PTR. The function will then set the required signature buffer length
 * in @pulSignatureLen and return CKR_OK.
 *
 * On operation completion, the @pulSignatureLen is updated to the correct
 * value when\:
 *
 *  - @pulSignatureLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulSignatureLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message signature operation complete.
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
 *  - CKR_MECHANISM_PARAM_INVALID:
 *      Mechanism parameter is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageSignInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		    CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign(hSession, pParameter, ulParameterLen, pData, ulDataLen,
			pSignature, pulSignatureLen, CKF_MESSAGE_SIGN,
			OP_ONE_SHOT);
}

/**
 * C_SignMessageBegin - Begin a multi-part message signature operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in/out] Message-specific parameter buffer.
 * @ulParameterLen: [in] Length of message-specific parameter.
 *
 * The message signature operation MUST have been initialized with
 * C_MessageSignInit(). This function begins the processing of a new message
 * in a multi-part message signature operation. A call to C_SignMessageBegin()
 * which results in an error terminates the current message signature operation.
 *
 * After calling C_SignMessageBegin(), the application should call
 * C_SignMessageNext() one or more times to process message data parts.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message signature operation reset for new message.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_MECHANISM_PARAM_INVALID:
 *      Mechanism parameter is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageSignInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			 CK_ULONG ulParameterLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return lib_sign_verify_reset(hSession, pParameter, ulParameterLen,
				     CKF_MESSAGE_SIGN);
}

/**
 * C_SignMessageNext - Continue a multi-part message signature operation.
 * @hSession: [in] Session handle.
 * @pParameter: [in] Message-specific parameter buffer.
 * @ulParameterLen: [in] Length of message-specific parameter.
 * @pData: [in] Message data part buffer.
 * @ulDataLen: [in] Length of message data part.
 * @pSignature: [out] Signature buffer (only for final call).
 * @pulSignatureLen: [in/out] Pointer to length of signature buffer (only for
 *                            final call).
 *
 * The message signature operation MUST have been initialized with
 * C_MessageSignInit() and a message started with C_SignMessageBegin().
 * This function may be called any number of times in succession to process
 * message data parts.
 *
 * When @pulSignatureLen is NULL_PTR, this function processes a message data
 * part without generating the signature (intermediate call).
 *
 * When @pulSignatureLen is not NULL_PTR, this function processes the final
 * message data part and generates the signature (final call). In this case,
 * the operation for the current message is terminated, but the message
 * signature operation remains active for processing additional messages.
 *
 * To query the required signature buffer length on the final call, set
 * @pSignature to NULL_PTR. The function will then set the required signature
 * buffer length in @pulSignatureLen and return CKR_OK.
 *
 * On final call completion, the @pulSignatureLen is updated to the correct
 * value when\:
 *
 *  - @pulSignatureLen is bigger than expected. In this case, operation
 *    succeeds.
 *  - @pulSignatureLen is shorter than expected. In this case, operation
 *    fails and returns CKR_BUFFER_TOO_SMALL.
 *
 * A call to C_SignMessageNext() which results in an error terminates the
 * current message signature operation.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message data part processed or signature generated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_ARGUMENTS_BAD:
 *      Operation bad state.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The output buffer is too small to hold the signature (final call only).
 *  - CKR_DATA_INVALID:
 *      Data length is invalid.
 *  - CKR_DATA_LEN_RANGE:
 *      Data length is invalid.
 *  - CKR_MECHANISM_PARAM_INVALID:
 *      Mechanism parameter is invalid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageSignInit().
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulSignatureLen)
{
	enum op_state state = NOT_INIT;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (pulSignatureLen)
		state = OP_END;
	else
		state = OP_NEXT;

	return lib_sign(hSession, pParameter, ulParameterLen, pData, ulDataLen,
			pSignature, pulSignatureLen, CKF_MESSAGE_SIGN, state);
}

/**
 * C_MessageSignFinal - Finish a multi-part message signature operation.
 * @hSession: [in] Session handle.
 *
 * The message signature operation MUST have been initialized with
 * C_MessageSignInit(). A call to C_MessageSignFinal() always terminates
 * the active message signature operation.
 *
 * This function is used to terminate the message signature operation without
 * processing any additional messages. It cancels the operation context and
 * releases associated resources.
 *
 * Return:
 *  - CKR_OK:
 *      Success. Message signature operation terminated.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      Session handle @hSession is invalid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      The operation must be initialized with C_MessageSignInit().
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by C_Initialize().
 *  - Other errors from the underlying implementation.
 */
CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	return libsess_cancel_opctx(hSession, CKF_MESSAGE_SIGN);
}
