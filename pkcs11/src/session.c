// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020 NXP
 */

#include "lib_session.h"
#include "util.h"

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

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return libsess_close(hSession);
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	return libsess_close_all(slotID);
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	if (!pInfo)
		return CKR_ARGUMENTS_BAD;

	return libsess_get_info(hSession, pInfo);
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	(void)hSession;
	(void)flags;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession;
	(void)pOperationState;
	(void)pulOperationStateLen;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	(void)hSession;
	(void)pOperationState;
	(void)ulOperationStateLen;
	(void)hEncryptionKey;
	(void)hAuthenticationKey;

	return CKR_FUNCTION_NOT_SUPPORTED;
}

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

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	if (!hSession)
		return CKR_SESSION_HANDLE_INVALID;

	return libsess_logout(hSession);
}
