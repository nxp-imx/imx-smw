// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2024, 2026 NXP
 */

#include "lib_session.h"
#include "util.h"

/**
 * C_OpenSession() - Opens a session between an application and a token.
 * @slotID: [in] The slot's ID.
 * @flags: [in] Flags from CK_SESSION_INFO.
 * @pApplication: [in] Pointer passed to callback.
 * @Notify: [in] Callback function.
 * @phSession: [out] Pointer to the location that receives the session handle.
 *
 * This function opens a session between an application and a token in a
 * particular slot.
 *
 * The @flags parameter must always set the :c:macro:`CKF_SERIAL_SESSION` flag.
 * If the :c:macro:`CKF_RW_SESSION` flag is set, the session is opened as
 * read/write, otherwise it is read-only.
 *
 * If @pApplication and @Notify are provided, they define a callback function
 * for notification events. Both must be set or both must be :c:macro:`NULL_PTR`.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      - The @phSession is NULL.
 *      - The @pApplication and @Notify are inconsistent.
 *  - CKR_SESSION_PARALLEL_NOT_SUPPORTED:
 *      The :c:macro:`CKF_SERIAL_SESSION` flag is not set.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_TOKEN_NOT_PRESENT:
 *      The token is not present.
 *  - CKR_TOKEN_NOT_RECOGNIZED:
 *      The token is not initialized.
 *  - CKR_HOST_MEMORY:
 *      Memory allocation failed.
 *  - CKR_SESSION_COUNT:
 *      The maximum number of sessions has been reached.
 *  - CKR_SESSION_READ_WRITE_SO_EXISTS:
 *      A read/write session already exists.
 *  - CKR_TOKEN_WRITE_PROTECTED:
 *      The token is write-protected.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (!phSession)
		return CKR_ARGUMENTS_BAD;

	if (!util_check_ptrs_null(2, pApplication, Notify) &&
	    !util_check_ptrs_set(2, pApplication, Notify))
		return CKR_ARGUMENTS_BAD;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	return libsess_open(slotID, flags, pApplication, Notify, phSession);
}

/**
 * C_CloseSession() - Closes a session between an application and a token.
 * @hSession: [in] The session's handle.
 *
 * This function closes a session between an application and a token.
 * When a session is closed, all session objects created by the session are
 * destroyed automatically.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return libsess_close(hSession);
}

/**
 * C_CloseAllSessions() - Closes all sessions with a token.
 * @slotID: [in] The token's slot ID.
 *
 * This function closes all sessions an application has with a token.
 * All session objects created by any session are destroyed automatically.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_SLOT_ID_INVALID:
 *      The slot ID is not valid.
 *  - CKR_TOKEN_NOT_PRESENT:
 *      The token is not present.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	return libsess_close_all(slotID);
}

/**
 * C_GetSessionInfo() - Obtains information about the session.
 * @hSession: [in] The session's handle.
 * @pInfo: [out] Pointer to the location that receives the session information.
 *
 * This function obtains information about a session.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pInfo is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libsess_get_info(hSession, pInfo);
}

/**
 * C_GetSessionValidationFlags() - Gets session validation flags.
 * @hSession: [in] The session's handle.
 * @type: [in] The type of validation flags.
 * @pFlags: [out] Pointer to the location that receives the flags.
 *
 * This function gets session validation flags.
 *
 * .. warning::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function is not supported.
 */
CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession,
				  CK_SESSION_VALIDATION_FLAGS_TYPE type,
				  CK_FLAGS_PTR pFlags)
{
	(void)hSession;
	(void)type;
	(void)pFlags;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_SessionCancel() - Cancels operations in a session.
 * @hSession: [in] The session's handle.
 * @flags: [in] Flags indicating which operations to cancel.
 *
 * This function cancels one or more operations in a session.
 *
 * .. warning::
 *    This function is not supported.
 *
 * Return:
 *  - CKR_FUNCTION_NOT_SUPPORTED:
 *      Function is not supported.
 */
CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	(void)hSession;
	(void)flags;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * C_GetOperationState() - Obtains the state of the cryptographic operation.
 * @hSession: [in] The session's handle.
 * @pOperationState: [out] Pointer to the location that receives the operation
 *                         state, or :c:macro:`NULL_PTR` to query the state size.
 * @pulOperationStateLen: [in/out] Pointer to the location that gives the size
 *                                 of @pOperationState buffer, or receives the
 *                                 operation state length.
 *
 * This function obtains a snapshot of the cryptographic operation state of
 * a session, encoded in a byte array.
 *
 * If @pOperationState is :c:macro:`NULL_PTR`, the function returns the required
 * buffer size in @pulOperationStateLen.
 *
 * If the @pOperationState is not :c:macro:`NULL_PTR`, the @pulOperationStateLen
 * contains the size of the buffer on input, and receives the actual state
 * length on output. If the buffer is too small, the function returns
 * CKR_BUFFER_TOO_SMALL.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @pulOperationStateLen is NULL.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_OPERATION_NOT_INITIALIZED:
 *      No operation is active in the session.
 *  - CKR_BUFFER_TOO_SMALL:
 *      The buffer provided is too small.
 *  - CKR_HOST_MEMORY:
 *      Memory allocation failed.
 *  - CKR_STATE_UNSAVEABLE:
 *      The operation state cannot be saved.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 *  - Other errors from the underlying implementation.
 */
CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	return libsess_get_operation_state(hSession, pOperationState,
					   pulOperationStateLen);
}

/**
 * C_SetOperationState() - Restores the state of the cryptographic operation.
 * @hSession: [in] The session's handle.
 * @pOperationState: [in] Pointer to the saved operation state.
 * @ulOperationStateLen: [in] Length of the saved operation state.
 * @hEncryptionKey: [in] Handle to encryption/decryption key (must be
 *                       CK_INVALID_HANDLE in this implementation).
 * @hAuthenticationKey: [in] Handle to signature/verification key (must be
 *                           CK_INVALID_HANDLE in this implementation).
 *
 * This function restores the cryptographic operation state of a session from
 * a byte array previously obtained with :c:func:`C_GetOperationState`.
 *
 * .. note::
 *    This implementation does not support key handles in this function.
 *    Both ``hEncryptionKey`` and ``hAuthenticationKey`` must be
 *    CK_INVALID_HANDLE.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      - The @pOperationState is NULL
 *      - The @ulOperationStateLen is 0.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_KEY_NOT_NEEDED:
 *      A key handle was provided when not needed.
 *  - CKR_SAVED_STATE_INVALID:
 *      The saved state is invalid or corrupted.
 *  - CKR_OPERATION_ACTIVE:
 *      An operation is already active in the session.
 *  - CKR_HOST_MEMORY:
 *      Memory allocation failed.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pOperationState || !ulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	if (hEncryptionKey != CK_INVALID_HANDLE ||
	    hAuthenticationKey != CK_INVALID_HANDLE)
		return CKR_KEY_NOT_NEEDED;

	return libsess_set_operation_state(hSession, pOperationState,
					   ulOperationStateLen);
}

/**
 * C_Login() - Logs a user into a token.
 * @hSession: [in] The session's handle.
 * @userType: [in] The user type (CKU_SO, CKU_USER, or CKU_CONTEXT_SPECIFIC).
 * @pPin: [in] The user's PIN (not used in this implementation).
 * @ulPinLen: [in] The length of the PIN (not used in this implementation).
 *
 * This function logs a user into a token.
 *
 * The @userType parameter can be\:
 *
 *   - CKU_SO: Security Officer
 *   - CKU_USER: Normal user
 *   - CKU_CONTEXT_SPECIFIC: Context-specific login
 *
 * .. note::
 *    This implementation does not support PIN management. The ``pPin`` and
 *    ``ulPinLen`` parameters are ignored.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @userType is invalid.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_USER_ALREADY_LOGGED_IN:
 *      A user is already logged in.
 *  - CKR_USER_ANOTHER_USER_ALREADY_LOGGED_IN:
 *      Another user is already logged in.
 *  - CKR_SESSION_READ_ONLY_EXISTS:
 *      A read-only session exists.
 *  - CKR_HOST_MEMORY:
 *      Memory allocation failed.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	(void)pPin;
	(void)ulPinLen;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (userType > CKU_CONTEXT_SPECIFIC)
		return CKR_ARGUMENTS_BAD;

	return libsess_login(hSession, userType);
}

/**
 * C_LoginUser() - Logs a user into a token with username.
 * @hSession: [in] The session's handle.
 * @userType: [in] The user type (CKU_SO, CKU_USER, or CKU_CONTEXT_SPECIFIC).
 * @pPin: [in] The user's PIN (not used in this implementation).
 * @ulPinLen: [in] The length of the PIN (not used in this implementation).
 * @pUsername: [in] The username (not used in this implementation).
 * @ulUsernameLen: [in] The length of the username (not used in this
 *                      implementation).
 *
 * This function logs a user into a token, providing both PIN and username.
 *
 * .. note::
 *    This implementation does not support PIN or username management.
 *    The ``pPin``, ``ulPinLen``, ``pUsername``, and ``ulUsernameLen``
 *    parameters are ignored.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_ARGUMENTS_BAD:
 *      The @userType is invalid.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_USER_ALREADY_LOGGED_IN:
 *      A user is already logged in.
 *  - CKR_USER_ANOTHER_USER_ALREADY_LOGGED_IN:
 *      Another user is already logged in.
 *  - CKR_SESSION_READ_ONLY_EXISTS:
 *      A read-only session exists.
 *  - CKR_HOST_MEMORY:
 *      Memory allocation failed.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		  CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	(void)pPin;
	(void)ulPinLen;
	(void)pUsername;
	(void)ulUsernameLen;

	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (userType > CKU_CONTEXT_SPECIFIC)
		return CKR_ARGUMENTS_BAD;

	return libsess_login(hSession, userType);
}

/**
 * C_Logout() - Logs a user out from a token.
 * @hSession: [in] The session's handle.
 *
 * This function logs a user out from a token.
 *
 * Return:
 *  - CKR_OK:
 *      Success.
 *  - CKR_SESSION_HANDLE_INVALID:
 *      The session handle is not valid.
 *  - CKR_USER_NOT_LOGGED_IN:
 *      No user is logged in.
 *  - CKR_GENERAL_ERROR:
 *      General error.
 *  - CKR_CRYPTOKI_NOT_INITIALIZED:
 *      The library has not been previously initialized by :c:func:`C_Initialize`.
 */
CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return libsess_logout(hSession);
}
